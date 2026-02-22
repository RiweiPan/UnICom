#ifndef LINUX_NAP_DMA_H
#define LINUX_NAP_DMA_H
#include <linux/dma-direct.h>
#include "nap.h"

#define MAX_DMA_CACHE_BUFFER_POOL_SIZE (16 * 1024 * 1024) // 16MB
#define DMA_CACHE_BUFFER_SIZE (256 * 1024) // 256KB

struct nap_dma_cache_buffer {
    int used;
    int buffer_len;
    unsigned long phys_addr;
    spinlock_t dma_buffer_lock;
    void *vaddr;
};

struct nap_dma_cache_buffer_ctx {
    int pos;
    int nr_dma_buffer;
    struct nap_dma_cache_buffer *dma_buffers;
};

static inline dma_addr_t nap_phys_to_dma(struct nap_dev *dev_entry, phys_addr_t paddr)
{
#ifdef NAP_KERNEL_VER_6
    return (dma_addr_t) paddr;
#else
    return paddr - ((dma_addr_t)dev_entry->pdev->dev.dma_pfn_offset << PAGE_SHIFT);
#endif
}

static inline phys_addr_t nap_dma_to_phys(struct nap_dev *dev_entry, dma_addr_t dma_addr)
{
#ifdef NAP_KERNEL_VER_6
    return (phys_addr_t) dma_addr;
#else
    return dma_addr + ((dma_addr_t)dev_entry->pdev->dev.dma_pfn_offset << PAGE_SHIFT);
#endif
}

struct nap_dma_addr_ctx *alloc_nap_dma_addr_ctx(struct nap_ns *ns_entry, unsigned long ubuf_addr, unsigned int ubuf_len, unsigned long offset);
void release_nap_dma_addr_ctx(struct nap_dma_addr_ctx *ctx);
int nap_ctx_map_buf_to_dma(struct nap_dma_addr_ctx *nap_dma_ctx);
int nap_ctx_unmap_buf_to_dma(struct nap_dma_addr_ctx *nap_dma_ctx);
int nap_dma_init(void);
void nap_dma_exit(void);
#endif