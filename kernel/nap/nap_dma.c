
#include <linux/mm.h>
#include "nap_dma.h"

#ifdef NAP_DEBUG_SUBMIT_DMA_COST
static unsigned long nap_debug_submit_dma_alloc_ov = 0;
static unsigned long nap_debug_submit_dma_alloc_cnt = 0;
#endif
static struct kmem_cache *nap_dma_ctx_slab;
static struct nap_dma_cache_buffer_ctx dma_cache_ctx;
#ifdef NAP_KERNEL_VER_6
static inline void nap_unpin_user_pages(struct page **pages, unsigned long npages)
{
	unsigned long index;

	/*
	 * TODO: this can be optimized for huge pages: if a series of pages is
	 * physically contiguous and part of the same compound page, then a
	 * single operation to the head page should suffice.
	 */
	for (index = 0; index < npages; index++)
		unpin_user_page(pages[index]);
}
#endif

static int nap_ctx_add_dma_addr(struct nap_dma_addr_ctx *nap_dma_ctx, phys_addr_t phys_addr)
{
    if(nap_dma_ctx->dma_addr_ofs >= nap_dma_ctx->nr_dma_pages) {
        nap_err_log("Error: out of range\n");
        return -EINVAL;
    }

    nap_dma_ctx->dma_addrs[nap_dma_ctx->dma_addr_ofs].phys_addr = phys_addr;
    nap_dma_ctx->dma_addr_ofs++;
    return 0;
}

static void map_ctx_reset_dma_addr(struct nap_dma_addr_ctx *nap_dma_ctx)
{
    int i;
    for(i = 0; i < nap_dma_ctx->nr_dma_pages; i++) {
        nap_dma_ctx->dma_addrs[i].phys_addr = 0;
    }
    nap_dma_ctx->dma_addr_ofs = 0;
}

// For this function: later we can consider use pin_user_pages_fast
// But note that we should use pin_user_pages_fast to release the pages 
// key refer function in linux 6.5 is iomap_dio_bio_iter
static int nap_ctx_map_ubuf_to_dma_fast(struct nap_dma_addr_ctx *nap_dma_ctx, unsigned long ubuf_addr, unsigned int ubuf_len) 
{
    int ret = 0, i;
    struct mm_struct *mm;
    unsigned long vaddr, paddr;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    // size_t in_page_offset = ubuf_addr & (PAGE_SIZE - 1); // we dont need this as we ensure the alignment in the page

    mm = current->mm;
    mmap_read_lock(mm);
    nap_dma_ctx->mapped = 1;
    for(i = 0; i < nap_dma_ctx->nr_dma_pages; i++) {
        vaddr = ubuf_addr + (i * PAGE_SIZE);
        nap_debug_log("ubuf to dma fast point 1 i = %d, vaddr = %lu\n", i, vaddr);
        pgd = pgd_offset(mm, vaddr);
        if (pgd_none(*pgd) || pgd_bad(*pgd)) {
            ret = -EFAULT;
            goto end;
        }
        nap_debug_log("ubuf to dma fast point 2 vaddr = %lu\n", vaddr);
        p4d = p4d_offset(pgd, vaddr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) {
            ret = -EFAULT;
            goto end;
        }
        nap_debug_log("ubuf to dma fast point 3 vaddr = %lu\n", vaddr);
        pud = pud_offset(p4d, vaddr);
        if (pud_none(*pud) || pud_bad(*pud)) {
            ret = -EFAULT;
            goto end;
        }
        nap_debug_log("ubuf to dma fast point 4 vaddr = %lu\n", vaddr);
        pmd = pmd_offset(pud, vaddr);
        if (!pmd_none(*pmd) &&
                (pmd_val(*pmd) & (_PAGE_PRESENT|_PAGE_PSE)) != _PAGE_PRESENT) {
            paddr = pmd_pfn(*pmd) << PAGE_SHIFT;
            nap_ctx_add_dma_addr(nap_dma_ctx, paddr);
            continue;
        } else if (pmd_none(*pmd) || pmd_bad(*pmd)) {
            ret = -EFAULT;
            goto end;
        }
        nap_debug_log("ubuf to dma fast point 5 vaddr = %lu\n", vaddr);
        pte = pte_offset_kernel(pmd, vaddr);
        if (!pte || !pte_present(*pte)) {
            ret = -EFAULT;
            goto end;
        }
        nap_debug_log("ubuf to dma fast point 6 vaddr = %lu\n", vaddr);
        paddr = pte_pfn(*pte) << PAGE_SHIFT;
        nap_ctx_add_dma_addr(nap_dma_ctx, paddr);
    }
end:
    if(ret) {
        nap_dma_ctx->mapped = 0;
        map_ctx_reset_dma_addr(nap_dma_ctx);
    }
    mmap_read_unlock(mm);
    return ret;
}


static int nap_ctx_map_ubuf_to_dma_slow(struct nap_dma_addr_ctx *nap_dma_ctx, unsigned long ubuf_addr, unsigned int ubuf_len)
{
    int ret = 0, i;
    phys_addr_t phys_addr;
    size_t in_page_offset = ubuf_addr & (PAGE_SIZE - 1);
    nap_debug_log("ubuf to dma slow point 1, in_page_offset = %lu\n", in_page_offset);
    nap_dma_ctx->pages = kvmalloc_array(nap_dma_ctx->nr_dma_pages, sizeof(struct page *), GFP_KERNEL);
    if(!nap_dma_ctx->pages) {
        nap_err_log("Error on allocating memory\n");
        return -ENOMEM;
    }
    nap_debug_log("ubuf to dma slow point 2\n");
    // nap_info_log("ubuf addr = %llu, nr_dma_pages = %d, in_page_offset = %lu\n", ubuf_addr, nap_dma_ctx->nr_dma_pages, in_page_offset);
#ifdef NAP_KERNEL_VER_6
    ret = pin_user_pages_fast(ubuf_addr, nap_dma_ctx->nr_dma_pages, FOLL_WRITE, nap_dma_ctx->pages);
#else
    ret = get_user_pages_fast(ubuf_addr, nap_dma_ctx->nr_dma_pages, FOLL_WRITE, nap_dma_ctx->pages);
#endif
    if (ret <= 0) {
        kvfree(nap_dma_ctx->pages);
        nap_dma_ctx->pages = NULL;
        nap_err_log("pin_user_pages_fast failed. ret = %d\n", ret);
        return -ENOMEM;
    }
    nap_debug_log("ubuf to dma slow point 3\n");
    if(ret != nap_dma_ctx->nr_dma_pages) {
err_out:
#ifdef NAP_KERNEL_VER_6
        nap_unpin_user_pages(nap_dma_ctx->pages, ret);
#else
        put_user_pages(nap_dma_ctx->pages, ret);
#endif
        kvfree(nap_dma_ctx->pages);
        nap_dma_ctx->pages = NULL;
        nap_err_log("nr pages not matched.\n");
        return -ENOMEM;
    }
    nap_debug_log("ubuf to dma slow point 4\n");
    nap_dma_ctx->mapped = 2;
    for(i = 0; i < nap_dma_ctx->nr_dma_pages; i++) {

        if(i == 0) {
            phys_addr = page_to_phys(nap_dma_ctx->pages[i]) + in_page_offset;
        } else {
            phys_addr = page_to_phys(nap_dma_ctx->pages[i]);
        }
        nap_debug_log("ubuf to dma slow point 5.1, phys_addr = %lu\n", phys_addr);
        phys_addr = nap_phys_to_dma(nap_dma_ctx->ns_entry->nap_dev_entry, phys_addr);
        nap_debug_log("ubuf to dma slow point 5.2, phys_addr = %lu\n", phys_addr);
        if(phys_addr == 0) {
            nap_dma_ctx->mapped = 0;
            nap_err_log("Error: phys_addr is 0\n");
            goto err_out;
        }
        nap_debug_log("&& Add Ubuf Addr: phys_addr = %lu\n", phys_addr);
        nap_ctx_add_dma_addr(nap_dma_ctx, phys_addr);
    }

    return 0;
}

static int nap_ctx_map_ubuf_to_dma(struct nap_dma_addr_ctx *nap_dma_ctx) 
{
    int ret = -EINVAL;
    if(nap_dma_ctx->nr_dma_pages == 0) {
        nap_err_log("Error: nr_dma_pages is 0\n");
        return -EINVAL;
    }
    nap_debug_log("Point 1: ubuf_addr = %lu, ubuf_len = %u, offset = %lu\n", nap_dma_ctx->ubuf_addr, nap_dma_ctx->ubuf_len, nap_dma_ctx->offset);
    /**
     * 1. 如果offset, ubuf_addr, ubuf_len都是aligned to page, 则可以直接使用nap_ctx_map_ubuf_to_dma_fast
     */
    if(nap_dma_ctx->ubuf_addr % PAGE_SIZE == 0 && nap_dma_ctx->ubuf_len % PAGE_SIZE == 0 && nap_dma_ctx->offset % PAGE_SIZE == 0) {
        ret = nap_ctx_map_ubuf_to_dma_fast(nap_dma_ctx, nap_dma_ctx->ubuf_addr, nap_dma_ctx->ubuf_len);
        if(ret == 0)
            return ret;
        nap_debug_log("Error: nap_ctx_map_ubuf_to_dma_fast failed, ret = %d\n", ret);
    }
    nap_debug_log("Point 2: ubuf_addr = %lu, ubuf_len = %u, offset = %lu\n", nap_dma_ctx->ubuf_addr, nap_dma_ctx->ubuf_len, nap_dma_ctx->offset);
    /**
     * 1. 如果offset, ubuf_addr, ubuf_len都是aligned to block, 则可以直接使用nap_ctx_map_ubuf_to_dma_slow
     * 2. 其实这里无需使用kbuf, 这个函数就能解决所有事, 但是这里先使用kbuf, 以后再优化
     */
    if(nap_dma_ctx->ubuf_addr % SECTOR_SIZE == 0 && nap_dma_ctx->ubuf_len % SECTOR_SIZE == 0 && nap_dma_ctx->offset % SECTOR_SIZE == 0) {
        nap_debug_log("Point 3: ubuf_addr = %lu, ubuf_len = %u, offset = %lu\n", nap_dma_ctx->ubuf_addr, nap_dma_ctx->ubuf_len, nap_dma_ctx->offset);
        ret = nap_ctx_map_ubuf_to_dma_slow(nap_dma_ctx, nap_dma_ctx->ubuf_addr, nap_dma_ctx->ubuf_len);
    }

    return ret;
}

static int nap_ctx_map_kbuf_to_dma(struct nap_dma_addr_ctx *nap_dma_ctx)
{
    int i, k;
    phys_addr_t phys_addr;
    struct nap_dma_cache_buffer *ndc_buf;
    if(nap_dma_ctx->nr_dma_pages * PAGE_SIZE > DMA_CACHE_BUFFER_SIZE) {
        nap_err_log("Error: ubuf_len is larger than DMA_CACHE_BUFFER_SIZE\n");
        return -ENOMEM;
    }
    
    for(i = 0; i < dma_cache_ctx.nr_dma_buffer; i++) {
        ndc_buf = &dma_cache_ctx.dma_buffers[i];

        spin_lock(&ndc_buf->dma_buffer_lock);
        if(ndc_buf->used == 0) {
            ndc_buf->used = 1;
            nap_dma_ctx->dma_cache_buffer_pos = i;
            phys_addr = nap_phys_to_dma(nap_dma_ctx->ns_entry->nap_dev_entry, ndc_buf->phys_addr);
            for(k = 0; k < nap_dma_ctx->nr_dma_pages; k++) {
                nap_ctx_add_dma_addr(nap_dma_ctx, phys_addr);
                phys_addr += PAGE_SIZE;
                nap_debug_log("Add Kbuf Addr: phys_addr = %lu\n", nap_dma_ctx->dma_addrs[k].phys_addr);
            }
            nap_dma_ctx->mapped = 3;
            nap_debug_log("Debug: mapped by kernel buffer, dma_cache_buffer_pos = %d, phys_addr = %lu\n", i, nap_dma_ctx->dma_addrs[0].phys_addr);
            spin_unlock(&ndc_buf->dma_buffer_lock);
            return 0;
        }
        spin_unlock(&ndc_buf->dma_buffer_lock);
    }
    
    return -ENOMEM;
}

int nap_ctx_map_buf_to_dma(struct nap_dma_addr_ctx *nap_dma_ctx)
{
    int ret = 0;
    ret = nap_ctx_map_ubuf_to_dma(nap_dma_ctx);
    if(ret == 0)
        return ret; // return if the fast way is successful

    if(unlikely(nap_dma_ctx->nr_dma_pages * PAGE_SIZE > DMA_CACHE_BUFFER_SIZE)) {
        nap_err_log("For now, nap does not support unaligned I/Os whose size is larger than 256KB\n");
        return -ENOMEM;
    }

    ret = nap_ctx_map_kbuf_to_dma(nap_dma_ctx);

    return ret;
}

int nap_ctx_unmap_buf_to_dma(struct nap_dma_addr_ctx *nap_dma_ctx)
{
    int ret = 0;
    if(nap_dma_ctx->mapped == 1)
        return 0;

    if(nap_dma_ctx->mapped == 2) {
#ifdef NAP_KERNEL_VER_6
        nap_unpin_user_pages(nap_dma_ctx->pages, nap_dma_ctx->nr_dma_pages);
#else
        put_user_pages(nap_dma_ctx->pages, nap_dma_ctx->nr_dma_pages);
#endif
        return 0;
    }

    if(nap_dma_ctx->mapped == 3) {
        struct nap_dma_cache_buffer *ndc_buf = &dma_cache_ctx.dma_buffers[nap_dma_ctx->dma_cache_buffer_pos];
        // size_t in_page_offset = nap_dma_ctx->ubuf_addr & (PAGE_SIZE - 1);
        // nap_info_log("ubuf addr = %llu, in page offset = %d, in_page_len = %d\n", nap_dma_ctx->ubuf_addr, in_page_offset, nap_dma_ctx->ubuf_len);
        // {
        //     int i;
        //     char *chbuf = ndc_buf->vaddr + 4096; // 385026
        //     for(i = 0; i < 10; i++) {
        //         unsigned int val = chbuf[i];
        //         nap_debug_log("[unmap] phys_addr = %lu, val = %u\n", nap_dma_ctx->dma_addrs[i].phys_addr, val);
        //     }
        // }
        if(copy_to_user((void *) nap_dma_ctx->ubuf_addr, ndc_buf->vaddr, nap_dma_ctx->ubuf_len)) {
            nap_err_log("Error on copying data\n");
            ret = -EFAULT;
        }

        spin_lock(&ndc_buf->dma_buffer_lock);
        ndc_buf->used = 0;
        spin_unlock(&ndc_buf->dma_buffer_lock);

        return ret;
    }

    return 0;
}

struct nap_dma_addr_ctx *alloc_nap_dma_addr_ctx(struct nap_ns *ns_entry, unsigned long ubuf_addr, unsigned int ubuf_len, unsigned long offset)
{
    unsigned long aligned_page_start, aligned_page_end;
    struct nap_dma_addr_ctx *ctx;
#ifdef NAP_DEBUG_SUBMIT_DMA_COST
    ktime_t kt_start, kt_end;
    kt_start = ktime_get();
#endif
    ctx = kmem_cache_alloc(nap_dma_ctx_slab, GFP_KERNEL); // kzalloc(sizeof(struct nap_dma_addr_ctx), GFP_KERNEL); // TODO: use kmem_cache?
    if(!ctx) {
        nap_err_log("Error on allocating memory\n");
        return NULL;
    }
#ifdef NAP_DEBUG_SUBMIT_DMA_COST
    kt_end = ktime_get();
    nap_debug_submit_dma_alloc_ov += ktime_to_ns(ktime_sub(kt_end, kt_start));
    nap_debug_submit_dma_alloc_cnt++;
#endif
    aligned_page_start = ubuf_addr / PAGE_SIZE;
    aligned_page_end = DIV_ROUND_UP(ubuf_addr + ubuf_len, PAGE_SIZE);

    ctx->mapped = 0;
    ctx->offset = offset;
    ctx->dma_cache_buffer_pos = 0;
    ctx->ns_entry = ns_entry;
    ctx->ubuf_addr = ubuf_addr;
    ctx->ubuf_len = ubuf_len;
    ctx->dma_addr_ofs = 0;
    ctx->nr_dma_pages = aligned_page_end - aligned_page_start;
    ctx->pages = NULL;

    ctx->dma_addrs = kzalloc(sizeof(struct nap_dma_addr) * ctx->nr_dma_pages, GFP_KERNEL);
    if(!ctx->dma_addrs) {
        nap_err_log("Error on allocating memory\n");
        kmem_cache_free(nap_dma_ctx_slab, ctx);
        return NULL;
    }

    return ctx;
}

void release_nap_dma_addr_ctx(struct nap_dma_addr_ctx *ctx)
{
    if(ctx) {
        if(ctx->dma_addrs) {
            kfree(ctx->dma_addrs);
        }
        if(ctx->pages) {
            kvfree(ctx->pages);
        }
        kmem_cache_free(nap_dma_ctx_slab, ctx);
    }
}

int nap_dma_init(void)
{
    int i, j, ret;
    nap_debug_log("nap_dma_init, point 1\n");
    nap_dma_ctx_slab = kmem_cache_create("nap_dma_ctx", sizeof(struct nap_dma_addr_ctx), 0, 0, NULL);
    if(!nap_dma_ctx_slab) {
        nap_err_log("Error on creating slab\n");
        return -ENOMEM;
    }
    
    // init dma buffer
    dma_cache_ctx.pos = 0;
    dma_cache_ctx.nr_dma_buffer = MAX_DMA_CACHE_BUFFER_POOL_SIZE / DMA_CACHE_BUFFER_SIZE;
    nap_debug_log("nap_dma_init, point 2, nr_dma_buffer = %d\n", dma_cache_ctx.nr_dma_buffer);
    dma_cache_ctx.dma_buffers = kzalloc(sizeof(struct nap_dma_cache_buffer) * dma_cache_ctx.nr_dma_buffer, GFP_KERNEL);
    if(!dma_cache_ctx.dma_buffers) {
        nap_err_log("Error on allocating memory\n");
        kmem_cache_destroy(nap_dma_ctx_slab);
        return -ENOMEM;
    }

    nap_debug_log("nap_dma_init, point 3\n");
    for(i = 0; i < dma_cache_ctx.nr_dma_buffer; i++) {
        struct nap_dma_cache_buffer *ndc_buf = &dma_cache_ctx.dma_buffers[i];

        ndc_buf->vaddr = (void *) __get_free_pages(GFP_KERNEL, get_order(DMA_CACHE_BUFFER_SIZE));
        if(!ndc_buf->vaddr) {
            nap_err_log("Error on allocating memory\n");
            kfree(ndc_buf);
            ret = -ENOMEM;
            goto err_out;
        }

        ndc_buf->buffer_len = DMA_CACHE_BUFFER_SIZE;
        ndc_buf->phys_addr = virt_to_phys(ndc_buf->vaddr);
        // nap_debug_log("nap_dma_init, point 3.1, phys_addr = %lu\n", ndc_buf->phys_addr);
        spin_lock_init(&ndc_buf->dma_buffer_lock);
    }
    nap_debug_log("nap_dma_init, point 4\n");
    return 0;
err_out:
    for(j = 0; j < i; j++) {
        free_pages((unsigned long) dma_cache_ctx.dma_buffers[j].vaddr, get_order(DMA_CACHE_BUFFER_SIZE));
    }
    kmem_cache_destroy(nap_dma_ctx_slab);
    return ret;
}

void nap_dma_exit(void)
{
    int i;
    for(i = 0; i < dma_cache_ctx.nr_dma_buffer; i++) {
        free_pages((unsigned long) dma_cache_ctx.dma_buffers[i].vaddr, get_order(DMA_CACHE_BUFFER_SIZE));
    }

    kfree(dma_cache_ctx.dma_buffers);

    if(nap_dma_ctx_slab) {
        kmem_cache_destroy(nap_dma_ctx_slab);
    }
#ifdef NAP_DEBUG_SUBMIT_DMA_COST
    nap_info_log("average nap_debug_submit_dma_alloc_ov = %lu ns\n", nap_debug_submit_dma_alloc_ov / nap_debug_submit_dma_alloc_cnt);
#endif
}
