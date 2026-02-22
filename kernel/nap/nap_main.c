
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/kmod.h>
#include <linux/proc_fs.h>
#include <linux/nap-map.h>
#include "nap.h"
#include "nap_dma.h"
#include "nap_nvme.h"

static struct proc_dir_entry *nap_proc_root;
static int ct_cpu_id = 31; // cpu id for the completion thread


#ifdef NAP_DEBUG_SUBMIT_COST
static unsigned long nap_debug_submit_cnt = 0;
static unsigned long nap_debug_cp_from_user = 0;
static unsigned long nap_debug_map_dma = 0;
static unsigned long nap_debug_alloc_req = 0;
static unsigned long nap_debug_io_submit = 0;
static unsigned long nap_debug_io_finished = 0;
static unsigned long nap_debug_dma_unmap = 0;
static unsigned long nap_debug_full_io_time = 0;
#endif

#ifdef NAP_DEBUG_NAP_POLL_NOTIFY_OVERHEAD
static unsigned long nap_debug_notify_ov = 0;
static unsigned long nap_debug_notify_cnt = 0;
#endif

#ifdef NAP_DEBUG_NAP_MAP_OVERHEAD
static unsigned long nap_debug_nap_map_ov = 0;
static unsigned long nap_debug_nap_map_cnt = 0;
#endif

static int nap_submit_one_request(struct nap_ns *ns_entry, struct nap_queue_pair *queue_pair, struct nap_rw_cmd *cmd)
{
    int ret;
    struct nap_dma_addr_ctx *nap_dma_ctx;
    struct nap_io_request *req;

    // printk("[nap-purepoll], rw = %d, len = %d, ofs = %lu, lba = %lu, vaddr = %lu, qidx = %d\n", cmd->rw, cmd->len, cmd->ofs, cmd->lba, cmd->vaddr, cmd->queue_idx);

    nap_dma_ctx = alloc_nap_dma_addr_ctx(ns_entry, cmd->vaddr, cmd->len, cmd->ofs);
    if(!nap_dma_ctx) {
        nap_err_log("Error on allocating memory\n");
        return -ENOMEM;
    }

    ret = nap_ctx_map_buf_to_dma(nap_dma_ctx);
    if(ret < 0) {
        nap_err_log("Error on getting physical address\n");
        release_nap_dma_addr_ctx(nap_dma_ctx);
        return ret;
    }

    req = alloc_io_request(queue_pair);
    req->dma_ctx = nap_dma_ctx;
    // nap_debug_log("point 2, rw = %d, len = %d, ofs = %lu, lba = %lu, vaddr = %lu, qidx = %d, dma_type = %d\n", 
    //     cmd.rw, cmd.len, cmd.ofs, cmd.lba, cmd.vaddr, cmd.queue_idx, nap_dma_ctx->mapped);
    
    /**
     * in the function nap_nvme_submit_io_request->nvme_submit_cmd
     * there is a lock to protect the queue for submission. Meanwhile, during the lock, memory barriers are set
     * so that the req->task must set before the lock.
     */
    req->task = current;
    if(cmd->rw == 1)
        nap_nvme_submit_io_request(queue_pair, req, nvme_cmd_write, cmd->lba);
    else
        nap_nvme_submit_io_request(queue_pair, req, nvme_cmd_read, cmd->lba);

#ifdef NAP_USE_NAP_POLL
    nvme_nap_poll(queue_pair, req->cmd_id);
#else
    nvme_poll(queue_pair, req->cmd_id);
#endif
    
    nap_ctx_unmap_buf_to_dma(nap_dma_ctx);

#ifdef NAP_USE_NAP_POLL
    queue_pair->io_complete_type = req->complete_type;
#endif

    free_io_request(req);
    release_nap_dma_addr_ctx(nap_dma_ctx);
    return 0;
}

#ifdef NAP_USE_NAP_POLL
static int nap_submit_multiple_requests(struct inode *uinode, struct nap_ns *ns_entry, struct nap_queue_pair *queue_pair, struct nap_rw_cmd *cmd)
{
    int ret = 0;
    u64 nr_lba, lba_ofs, in_sector_ofs;
    u64 remaining_nr_lba, remaining_bytes, processed_bytes;
    u64 original_ofs = cmd->ofs;
    u64 original_len = cmd->len;
    u64 original_vaddr = cmd->vaddr;
    u64 start_page, end_page;
#ifdef NAP_DEBUG_NAP_MAP_OVERHEAD
    ktime_t nmap_start, nmap_end;
#endif

    u64 file_size = i_size_read(uinode);
    
    // 检查请求是否超出文件范围
    if (original_ofs >= file_size) {
        return 0;
    }
    
    // 调整请求长度，确保不超出文件范围
    if (original_ofs + original_len > file_size) {
        original_len = file_size - original_ofs;
        original_len = round_up(original_len, 512);
        cmd->len = original_len; // 更新命令中的长度
    }

    start_page = original_ofs / PAGE_SIZE;
    end_page = (original_ofs + original_len - 1) / PAGE_SIZE;
    nr_lba = end_page - start_page + 1; // calculate nr of lbas considering block unaligned and page unaligned

    lba_ofs = original_ofs / PAGE_SIZE;
    in_sector_ofs = (original_ofs % PAGE_SIZE) / 512; // in-page offset, sector aligned
    remaining_nr_lba = nr_lba;
    processed_bytes = 0;

    // printk("[nap] original ofs = %llu, original len = %llu, original vaddr = %llu, uinode = %d, in_sector_ofs = %d, file size = %d\n", original_ofs, original_len, original_vaddr, uinode->i_ino, in_sector_ofs, i_size_read(uinode));

    if(in_sector_ofs > 0) { // handle the scenario of I/O not aligned to PAGE_SIZE
        u64 pba = 0, first_chunk_len;

#ifdef NAP_DEBUG_NAP_MAP_OVERHEAD
        nmap_start = ktime_get();
#endif
        int nr_read = nmap_lookup_block_address(uinode, lba_ofs, 1, &pba);
        if(nr_read <= 0) {
            if(nr_read == 0) {
                // TODO: shall we handle file hole here?
                nap_err_log("No mapping found for file size = %llu, original_ofs = %llu, lba_ofs = %llu, lba_size = %llu, ino = %lu\n", 
                       i_size_read(uinode), original_ofs, lba_ofs, remaining_nr_lba, uinode->i_ino);
                return -EINVAL;
            }
            nap_err_log("Error on looking up block address, lba_ofs = %llu, lba_size = %llu, ret = %d\n", lba_ofs, remaining_nr_lba, nr_read);
            return nr_read;
        }
#ifdef NAP_DEBUG_NAP_MAP_OVERHEAD
        nmap_end = ktime_get();
        nap_debug_nap_map_ov += ktime_to_ns(ktime_sub(nmap_end, nmap_start));
        nap_debug_nap_map_cnt += 1;
#endif
        // 计算第一个非对齐部分的长度
        first_chunk_len = min_t(u64, PAGE_SIZE - (original_ofs % PAGE_SIZE), original_len);
        
        cmd->lba = pba * 8 + in_sector_ofs;
        cmd->ofs = original_ofs;
        cmd->len = first_chunk_len;
        cmd->vaddr = original_vaddr;
        
        // printk("[nap-nappoll-0], rw = %d, len = %d, ofs = %lu, lba = %lu, vaddr = %lu, qidx = %d, in_sector_ofs = %lu\n", cmd->rw, cmd->len, cmd->ofs, cmd->lba, cmd->vaddr, cmd->queue_idx, in_sector_ofs);
        
        // printk("[nap-nappoll-0], remaining_nr_lba = %lu, nr_read = %lu, current_chunk_len = %lu\n", remaining_nr_lba, nr_read, first_chunk_len);

        // TODO: 给requests一个status, 用于返回给上层
        ret = nap_submit_one_request(ns_entry, queue_pair, cmd);
        if (ret < 0) {
            nap_err_log("Error on submitting first IO request, lba = %llu, ofs = %llu, len = %llu, ret = %d\n", 
                       cmd->lba, cmd->ofs, cmd->len, ret);
            return ret;
        }

        // 更新计数器
        lba_ofs += 1;
        processed_bytes += first_chunk_len;
        remaining_nr_lba -= 1;
        in_sector_ofs = 0; // 后续部分都是页对齐的

        // printk("[nap], rw = %d, len = %d, ofs = %lu, lba = %lu, vaddr = %lu, qidx = %d, processed_bytes = %lu, uniode = %d\n", 
        //     cmd->rw, cmd->len, cmd->ofs, cmd->lba, cmd->vaddr, cmd->queue_idx, processed_bytes, uinode->i_ino);
    }

    while (remaining_nr_lba > 0) {
        int nr_read;
        u64 pba = 0;
        u64 current_chunk_len, actual_nr_read;
        
#ifdef NAP_DEBUG_NAP_MAP_OVERHEAD
        nmap_start = ktime_get();
#endif
        // Notes: this function is page-aligned
        nr_read = nmap_lookup_block_address(uinode, lba_ofs, remaining_nr_lba, &pba);
        if(nr_read <= 0) {
            if(nr_read == 0) {
                // TODO: shall we handle file hole here?
                nap_err_log("No mapping found for file size = %llu, original_ofs = %llu, lba_ofs = %llu, lba_size = %llu, ino = %lu\n", 
                       i_size_read(uinode), original_ofs, lba_ofs, remaining_nr_lba, uinode->i_ino);
                ret = -EINVAL;
                break;
            }
            nap_err_log("Error on looking up block address, lba_ofs = %llu, lba_size = %llu, ret = %d\n", lba_ofs, remaining_nr_lba, nr_read);
            ret = nr_read;
            break;
        }
#ifdef NAP_DEBUG_NAP_MAP_OVERHEAD
        nmap_end = ktime_get();
        nap_debug_nap_map_ov += ktime_to_ns(ktime_sub(nmap_end, nmap_start));
        nap_debug_nap_map_cnt += 1;
#endif
        // split to 128 KB I/O due to unknown POWER LOSS NOTIFICATION issue
        actual_nr_read = min_t(u64, nr_read, MAX_PER_BIO_PAGES);

        remaining_bytes = original_len - processed_bytes;
        current_chunk_len = min_t(u64, actual_nr_read * PAGE_SIZE, remaining_bytes);

        cmd->lba = pba * 8; // translate to sector aligned address
        cmd->ofs = original_ofs + processed_bytes; // update offset
        cmd->len = current_chunk_len;
        cmd->vaddr = original_vaddr + processed_bytes; // update user buffer

        // printk("[nap-nappoll], rw = %d, len = %d, ofs = %lu, lba = %lu, vaddr = %lu, qidx = %d, in_sector_ofs = %lu\n", cmd->rw, cmd->len, cmd->ofs, cmd->lba, cmd->vaddr, cmd->queue_idx, in_sector_ofs);
        
        // printk("[nap-nappoll], remaining_nr_lba = %lu, nr_read = %lu, actual_nr_read = %lu, current_chunk_len = %lu\n", remaining_nr_lba, nr_read, actual_nr_read, current_chunk_len);

        ret = nap_submit_one_request(ns_entry, queue_pair, cmd);
        if(ret < 0) {
            nap_err_log("Error on submitting IO request, lba = %lu, ofs = %lu, len = %u, ret = %d\n", cmd->lba, cmd->ofs, cmd->len, ret);
            break;
        }

        lba_ofs += actual_nr_read;
        processed_bytes += current_chunk_len;
        remaining_nr_lba -= actual_nr_read;

        // nap_info_log("[nap-nappoll] processe bytes = %lu, current_chunk_len = %lu\n", processed_bytes, current_chunk_len);
        // printk("[nap], rw = %d, len = %d, ofs = %lu, lba = %lu, vaddr = %lu, qidx = %d, processed_bytes = %lu, uinode = %d\n", 
        //     cmd->rw, cmd->len, cmd->ofs, cmd->lba, cmd->vaddr, cmd->queue_idx, processed_bytes, uinode->i_ino);
    } 

    return ret;
}
#endif

static int nap_ioc_submit_io(struct file *file, unsigned long arg)
{
    int ret = 0, qidx; 
    struct nap_ns *ns_entry = pde_data(file->f_inode);
    struct nap_rw_cmd cmd;
    struct nap_queue_pair *queue_pair;
#ifdef NAP_USE_NAP_POLL
    struct fd f;
    struct file *ufile;
    struct inode *uinode;
#endif

    if (copy_from_user(&cmd, (struct nap_rw_cmd __user *) arg, sizeof(cmd)))
		return -EFAULT;

    qidx = get_qidx(ns_entry);
    queue_pair = get_io_queue_by_qidx(ns_entry, qidx);
    if(!queue_pair) {
        nap_err_log("Error on getting io queue\n");
        return -EINVAL;
    }

#ifdef NAP_USE_NAP_POLL
    f = fdget(cmd.fd);
    if (!f.file) {
        return -EBADF;
    }

    ufile = f.file;
    uinode = ufile->f_inode;

    if (!uinode || !uinode->i_op) {
        ret = -EINVAL;
        goto out;
    }

    set_my_io_thread_flag(1); // let the scheduler notice this thread

    ret = nap_submit_multiple_requests(uinode, ns_entry, queue_pair, &cmd);
out:
    fdput(f);
#else
    ret = nap_submit_one_request(ns_entry, queue_pair, &cmd);
#endif

    return ret;
}

static int nap_ioc_register_file(struct file *file, unsigned long arg)
{
    struct nap_reg reg;
    struct nap_ns *ns_entry = pde_data(file->f_inode);

    if (copy_from_user(&reg, (struct nap_reg __user *) arg, sizeof(reg)))
        return -EFAULT;

    reg.queue_idx = get_qidx(ns_entry);
    if(reg.queue_idx < 0)
        return -EINVAL;

    // nap_info_log("fname = %s, inode = %u with queue index %d, pid = %d, pname = %s\n", 
    //     file->f_path.dentry->d_iname, file->f_inode->i_ino, reg.queue_idx, current->pid, current->comm);
    if(copy_to_user((struct nap_reg __user *) arg, &reg, sizeof(reg))) {
        nap_err_log("Error on copy to user\n");
        // here we do not release resources...
        return -EFAULT;
    }
    return 0;
}

static int nap_ioc_unregister_file(struct file *file, unsigned long arg)
{
    struct nap_reg reg;

    if (copy_from_user(&reg, (struct nap_reg __user *) arg, sizeof(reg)))
        return -EFAULT;

    // normally, we should minus 1 for the nr_file in the specific queue
    // this would be used for load balancing if we have more time.

    return 0;
}

static long nap_ioc_set_flag(struct file *file, unsigned long param)
{
    unsigned long fflag = 0;

    if(copy_from_user(&fflag, (unsigned long __user *)param, sizeof(fflag)))
        return -EFAULT;
    
    set_my_io_thread_flag(fflag);

    return 0;
}

#ifdef NAP_USE_NAP_POLL
static int nap_io_complete_task(void *data)
{
    int i, complete_cnt = 0, total_complete_cnt = 0;
    int cpuid = ct_cpu_id;
    struct nap_ns *ns_entry = (struct nap_ns *) data;
    struct nap_io_queue_ctx *io_queues = ns_entry->nap_io_queues;
#ifdef NAP_DEBUG_NAP_IO_COMPLETE_THREAD
    unsigned long queue_stat[50] = {0};
    unsigned long queue_total_stat[50] = {0};
    if(ns_entry->nap_io_queues->nr_queues > 50) {
        nap_err_log("The number of queues is too large\n");
        return -EINVAL;
    }
#endif
    // bind core
    nap_info_log("The dedicated thread is bound to CPUID %d\n", cpuid);
    set_cpus_allowed_ptr(current, cpumask_of(cpuid));


    /**
     * The reason why our design cannot have a similar sum value as IRQ:
     * 1. Of course our design uses one CPU cores, resulting in a lower sum value.
     * 2. When the SSD saturates, I/O requests are queued becauase it has to wait for I/O completion of previous I/OS.
     *      This limits the I/O submission rate, and does not saturate the dedicated thread, e.g., 855k IOPS is not enough.
     *      We need to consider how to reduce the cost when SSD saturates, e.g., 
     *           1. the dedicated threads know when the SSD is saturated (IOPS does not increase or by setting a hint in user space) and know if it is also saturated (by detecting the efficiency of each loop)
     *           2. in this scenario, we can set throttling, e.g., reduce CPU utilization for this dedicated thread.
     *  
     * !! Why our design cannot have a similar low latency like Poll:
     * 1. When the SSD is saturated, I/Os are queued and have to wait for I/O completion of previous I/Os.
     * 2. For poll, it does not need to queue for wake up, and it can be waken up immediately.
     */
    while(1) {
        if(kthread_should_stop()) {
            nap_info_log("Exit dedicated thread\n");
            break;
        }
#ifdef NAP_DEBUG_NAP_POLL_NOTIFY_OVERHEAD
        ktime_t start_time = ktime_get();
#endif
        total_complete_cnt = 0;
        for(i = 0; i < io_queues->nr_queues; i++) {
            struct nap_queue_pair *queue_pair = &io_queues->io_queues[i];
            complete_cnt = nvme_nap_complete_io(queue_pair);
            total_complete_cnt += complete_cnt;
#ifdef NAP_DEBUG_NAP_IO_COMPLETE_THREAD
            queue_stat[i] = complete_cnt;
            queue_total_stat[i] += complete_cnt;
#endif
        }
        if(total_complete_cnt == 0) {
            cond_resched();
        } else {
#ifdef NAP_DEBUG_NAP_IO_COMPLETE_THREAD
        nap_info_log("q[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu \n",
            0, queue_stat[0], 1, queue_stat[1], 2, queue_stat[2], 3, queue_stat[3], 4, queue_stat[4], 5, queue_stat[5], 6, queue_stat[6], 7, queue_stat[7], 8, queue_stat[8], 9, queue_stat[9],
            10, queue_stat[10], 11, queue_stat[11], 12, queue_stat[12], 13, queue_stat[13], 14, queue_stat[14], 15, queue_stat[15], 16, queue_stat[16], 17, queue_stat[17], 18, queue_stat[18], 19, queue_stat[19],
            20, queue_stat[20], 21, queue_stat[21], 22, queue_stat[22], 23, queue_stat[23], 24, queue_stat[24], 25, queue_stat[25], 26, queue_stat[26], 27, queue_stat[27], 28, queue_stat[28], 29, queue_stat[29],
            30, queue_stat[30], 31, queue_stat[31], 32, queue_stat[32], 33, queue_stat[33], 34, queue_stat[34], 35, queue_stat[35], 36, queue_stat[36], 37, queue_stat[37], 38, queue_stat[38], 39, queue_stat[39],
            40, queue_stat[40], 41, queue_stat[41], 42, queue_stat[42], 43, queue_stat[43], 44, queue_stat[44], 45, queue_stat[45], 46, queue_stat[46], 47, queue_stat[47], 48, queue_stat[48], 49, queue_stat[49]);

        // nap_info_log("t[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu,[%d]=%lu \n",
        //     0, queue_total_stat[0], 1, queue_total_stat[1], 2, queue_total_stat[2], 3, queue_total_stat[3], 4, queue_total_stat[4], 5, queue_total_stat[5], 6, queue_total_stat[6], 7, queue_total_stat[7], 8, queue_total_stat[8], 9, queue_total_stat[9],
        //     10, queue_total_stat[10], 11, queue_total_stat[11], 12, queue_total_stat[12], 13, queue_total_stat[13], 14, queue_total_stat[14], 15, queue_total_stat[15], 16, queue_total_stat[16], 17, queue_total_stat[17], 18, queue_total_stat[18], 19, queue_total_stat[19],
        //     20, queue_total_stat[20], 21, queue_total_stat[21], 22, queue_total_stat[22], 23, queue_total_stat[23], 24, queue_total_stat[24], 25, queue_total_stat[25], 26, queue_total_stat[26], 27, queue_total_stat[27], 28, queue_total_stat[28], 29, queue_total_stat[29],
        //     30, queue_total_stat[30], 31, queue_total_stat[31], 32, queue_total_stat[32], 33, queue_total_stat[33], 34, queue_total_stat[34], 35, queue_total_stat[35], 36, queue_total_stat[36], 37, queue_total_stat[37], 38, queue_total_stat[38], 39, queue_total_stat[39],
        //     40, queue_total_stat[40], 41, queue_total_stat[41], 42, queue_total_stat[42], 43, queue_total_stat[43], 44, queue_total_stat[44], 45, queue_total_stat[45], 46, queue_total_stat[46], 47, queue_total_stat[47], 48, queue_total_stat[48], 49, queue_total_stat[49]);
#endif
#ifdef NAP_DEBUG_NAP_POLL_NOTIFY_OVERHEAD
            ktime_t end_time = ktime_get();
            nap_debug_notify_ov += ktime_to_ns(ktime_sub(end_time, start_time));
            nap_debug_notify_cnt += total_complete_cnt;
#endif
        }
        cpu_relax(); // this is important, otherwise, the CPU utilization will be very high
    }

    return 0;
}
#endif

// This function should not be called by I/O threads; instead, it should be called by the manager.
static int nap_ioc_enable(struct file *file, unsigned long arg)
{
    int nr_queues, nr_created_queues = 0;
    int ret;
    struct nap_ns *ns_entry = pde_data(file->f_inode);
    struct nap_dev *dev_entry = ns_entry->nap_dev_entry;

    if (copy_from_user(&nr_queues, (int __user *) arg, sizeof(nr_queues)))
		return -EFAULT;

    nap_info_log("Enable NAP functionality! Expected Queue = %d, Dev-Name: nvme%dn%u\n", nr_queues, dev_entry->ndev->ctrl.instance, ns_entry->ns->head->ns_id);

    down_write(&dev_entry->ctrl_lock);
    if(ns_entry->nap_io_queues->intilized == 1) {
        nap_info_log("The NAP driver is already initialized!\n");
        nr_created_queues = ns_entry->nap_io_queues->nr_queues;
        goto out;
    }
    
    ret = nap_init_io_queues(ns_entry, nr_queues);
    if(ret <= 0 || ns_entry->nap_io_queues->nr_queues == 0) {
        nap_err_log("Error on init io queues\n");
        if(ret == 0)
            ret = -ENOMEM;
        goto out;
    }

    ret = 0;
    nr_created_queues = ns_entry->nap_io_queues->nr_queues;
    nap_info_log("Allocate %d NVMe I/O queues. Dev Name: nvme%dn%u\n", nr_created_queues, dev_entry->ndev->ctrl.instance, ns_entry->ns->head->ns_id);

    // create a dedicated thread for polling I/O completion
    // consider this function:    kthread_create_on_cpu
#ifdef NAP_USE_NAP_POLL
    if(nr_created_queues > 0) {
        ns_entry->io_complete_task = kthread_run(nap_io_complete_task, ns_entry, "nap_io_complete_task");
        if(IS_ERR(ns_entry->io_complete_task)) {
            nap_err_log("Error on creating dedicated thread\n");
            nap_release_io_queues(ns_entry);
            ret = PTR_ERR(ns_entry->io_complete_task);
            goto out;
        }
    }
#endif

    enable_ts_pick_next_task_stat(1);
#ifdef NAP_KERNEL_VER_6
    enable_ts_sched_core_stat(1);
#endif
    ns_entry->nap_io_queues->intilized = 1;
out:
    up_write(&dev_entry->ctrl_lock);
    if(copy_to_user((int __user *) arg, &nr_created_queues, sizeof(nr_created_queues))) {
        nap_err_log("Error on copy to user\n");
        // here we do not release resources...
        return -EFAULT;
    }
    return ret;
}

static int nap_ioc_disable(struct file *file, unsigned long arg)
{
    int ret;
    struct nap_ns *ns_entry = pde_data(file->f_inode);
    struct nap_dev *dev_entry = ns_entry->nap_dev_entry;
    
    nap_info_log("Disable NAP functionality!\n");
    down_write(&dev_entry->ctrl_lock);

    if(ns_entry->nap_io_queues->intilized == 0) {
        nap_info_log("The NAP driver is already disabled!\n");
        goto out;
    }
#ifdef NAP_USE_NAP_POLL
    if(ns_entry->io_complete_task) {
        kthread_stop(ns_entry->io_complete_task);
        ns_entry->io_complete_task = NULL;
    }
#endif
    ret = nap_release_io_queues(ns_entry);
    if(ret < 0) {
        nap_err_log("Error on release io queues\n");
        goto out;
    }

    enable_ts_pick_next_task_stat(0);
    print_ts_pick_next_task_stat();
#ifdef NAP_KERNEL_VER_6
    enable_ts_sched_core_stat(0);
    print_ts_sched_core_stat();
#else
    printk_nap_sched_core_statistics();
#endif
    ns_entry->nap_io_queues->intilized = 0;
out:
    up_write(&dev_entry->ctrl_lock);
    return 0;
}

static long nap_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret;

    switch (cmd) {
        case NAP_IOC_ENABLE:
            ret = nap_ioc_enable(file, arg);
            break;
        case NAP_IOC_DISABLE:
            ret = nap_ioc_disable(file, arg);
            break;
        case NAP_IOC_SUBMIT_IO:
            ret = nap_ioc_submit_io(file, arg);
            break;
        case NAP_IOC_REGISTER_FILE:
            ret = nap_ioc_register_file(file, arg);
            break;
        case NAP_IOC_UNREGISTER_FILE:
            ret = nap_ioc_unregister_file(file, arg);
            break;
        case NAP_IOC_SET_FLAG:
            ret = nap_ioc_set_flag(file, arg);
            break;
        default:
            ret = -EINVAL;
            nap_err_log("Invalid IOCTL\n");
            break;
    }
    return ret;
}

#ifdef NAP_KERNEL_VER_6
static const struct proc_ops nap_ns_fops = {
    .proc_ioctl = nap_ioctl,
};
#else
static const struct file_operations nap_ns_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = nap_ioctl,
};
#endif

static int __init nap_init(void)
{
    int ret;

    ret = request_module("nvme");
    if (ret < 0) {
        nap_err_log("Cannot find NVMe driver\n");
        return -1;
    }

    nap_proc_root = proc_mkdir("nap", NULL);
    if (!nap_proc_root) {
        nap_err_log("Couldn't create proc entry\n");
        return -1;
    }

    if (init_nvme_devices(nap_proc_root, &nap_ns_fops) != 0) {
        nap_err_log("Couldn't find NVMe device\n");
        return -1;
    }

    nap_dma_init();
    init_nvme_request_settings(NULL);

    nap_info_log("Initialized NAP module\n");
#ifdef NAP_USE_NAP_POLL
#pragma message("NAP_POLL is enabled")
#else
#pragma message("PURE_POLL is enabled")
#endif
#ifdef NAP_KERNEL_VER_6
#pragma message("NAP_KERNEL_VER_6 is enabled")
#else
#pragma message("NAP_KERNEL_VER_5 is enabled")
#endif
    return 0;
}

static void __exit nap_exit(void)
{
    nap_info_log("Exiting NAP module\n");
#ifdef NAP_DEBUG_SUBMIT_COST
    {
        nap_info_log("average nap_debug_cp_from_user = %ld ns\n", nap_debug_cp_from_user / nap_debug_submit_cnt);
        nap_info_log("average nap_debug_map_dma = %ld ns\n", nap_debug_map_dma / nap_debug_submit_cnt);
        nap_info_log("average nap_debug_alloc_req = %ld ns\n", nap_debug_alloc_req / nap_debug_submit_cnt);
        nap_info_log("average nap_debug_io_submit = %ld ns\n", nap_debug_io_submit / nap_debug_submit_cnt);
        nap_info_log("average nap_debug_io_finished = %ld ns\n", nap_debug_io_finished / nap_debug_submit_cnt);
        nap_info_log("average nap_debug_dma_unmap = %ld ns\n", nap_debug_dma_unmap / nap_debug_submit_cnt);
        nap_info_log("average nap_debug_full_io_time = %ld ns\n", nap_debug_full_io_time / nap_debug_submit_cnt);
    }
#endif
#ifdef NAP_DEBUG_NAP_POLL_NOTIFY_OVERHEAD
    {
        nap_info_log("average nap_debug_notify_ov = %ld ns, complete cnt = %d\n", nap_debug_notify_ov / nap_debug_notify_cnt, nap_debug_notify_cnt);
    }
#endif
#ifdef NAP_DEBUG_NAP_MAP_OVERHEAD
    {
         nap_info_log("average nap_debug_nap_map_ov = %ld ns, complete cnt = %d\n", nap_debug_nap_map_ov / nap_debug_nap_map_cnt, nap_debug_nap_map_cnt);
    }
#endif
    exit_nvme_request_settings();
    nap_dma_exit();
    free_nvme_devices();
    proc_remove(nap_proc_root); 
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Riwei Pan");
MODULE_DESCRIPTION("NAP module. Some implementations of this module refers to the implementation of BypassD.");

module_param(ct_cpu_id, int , S_IRUGO);
module_init(nap_init);
module_exit(nap_exit);
