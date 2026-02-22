#include <linux/sched.h>
#include <linux/proc_fs.h>
#include "nap_nvme.h"

#ifdef NAP_DEBUG_QUEUE_IDX_TRACE
static unsigned long queue_idx_io_cnt[MAX_USER_QUEUES] = {0};
#endif

#ifdef NAP_DEBUG_PER_IO_TIMESTAMP
static unsigned long avg_per_io_time = 0;
static unsigned long avg_per_io_time_cnt = 0;
static unsigned long max_per_io_time = 0;
static unsigned long min_per_io_time = ULONG_MAX;

static unsigned long avg_per_io_nr_check = 0;
static unsigned long avg_per_io_nr_check_cnt = 0;
static unsigned long max_per_io_nr_check = 0;
static unsigned long min_per_io_nr_check = ULONG_MAX;

#ifdef NAP_DEBUG_PER_IO_TIMESTAMP_REPONSE_TIME
static unsigned long avg_per_io_max_check_time = 0;
static unsigned long avg_per_io_max_check_time_cnt = 0;
static unsigned long max_per_io_max_check_time = 0;
static unsigned long min_per_io_max_check_time = ULONG_MAX;

static unsigned long avg_per_io_response_time = 0;
static unsigned long avg_per_io_response_time_cnt = 0;
static unsigned long max_per_io_response_time = 0;
static unsigned long min_per_io_response_time = ULONG_MAX;

static unsigned long avg_per_io_response_time2 = 0;
static unsigned long avg_per_io_response_time_cnt2 = 0;
static unsigned long max_per_io_response_time2 = 0;
static unsigned long min_per_io_response_time2 = ULONG_MAX;
spinlock_t per_io_timestamp_lock;
#endif
#endif

#ifdef NAP_DEBUG_CACHE_TEST
static unsigned long cache_test_cnt = 0;
#endif

static unsigned long cskip_1_io_reserved = 0;

#ifdef NAP_DEBUG_DMA_MAPPING_TYPE_TRACE
static unsigned long dma_map_type_cnt[5] = {0};
static unsigned long dma_map_type_prp_cnt[5] = {0};
#endif

#ifdef NAP_DEBUG_NVME_POLL_OVERHEAD
static unsigned long avg_per_io_complete_time = 0;
static unsigned long avg_per_io_complete_cnt = 0;
static unsigned long avg_per_io_loop_tries = 0;
static unsigned long avg_per_io_loop_tries_cnt = 0;
#endif

#ifdef NAP_DEBUG_RETRY_CNT
static unsigned long avg_per_io_retry_cnt = 0;
static unsigned long avg_per_io_retry_cnt_cnt = 0;
#endif

#ifdef NAP_DEBUG_IOCT_CNT
static unsigned long avg_per_ioct_poll = 0;
static unsigned long avg_per_ioct_yield = 0;
static unsigned long avg_per_ioct_nap = 0;
static unsigned long avg_nr_running = 0;
static unsigned long avg_nr_running_cnt = 0;
#endif

#ifdef NAP_DEBUG_IO_THREAD_CPU_CHANGE_CNT
static unsigned long io_thread_wake_affine_cpu_dist_cnt[100] = {0};
#endif

#ifdef NAP_DEBUG_NVME_SETUP_COST
static unsigned long nap_debug_nvme_setup_prp_lat = 0;
static unsigned long nap_debug_nvme_setup_prp_lat_cnt = 0;
static unsigned long nap_debug_nvme_setup_cmd_lat = 0;
static unsigned long nap_debug_nvme_setup_cmd_lat_cnt = 0;
static unsigned long nap_debug_nvme_submit_cmd_lat = 0;
static unsigned long nap_debug_nvme_submit_cmd_lat_cnt = 0;
#endif

#ifdef NAP_DEBUG_UPDATE_TAG_OVERHEAD
static unsigned long nap_debug_nvme_submit_update = 0;
static unsigned long nap_debug_nvme_submit_update_cnt = 0;
static unsigned long nap_debug_nvme_complete_update = 0;
static unsigned long nap_debug_nvme_complete_update_cnt = 0;
#endif

#ifdef NAP_PER_CPU_IO_REQ_ALLICATION
#define MAX_CPUS 64
static DEFINE_PER_CPU(struct nap_io_request *, current_req);
static DEFINE_PER_CPU(atomic_t, cpu_cmd_id);
#endif


#define SECTOR_ALIGN(len)   (((len) + ((SECTOR_SIZE) - 1)) & (~((typeof(len))(SECTOR_SIZE)-1)))

struct nap_io_request *alloc_io_request(struct nap_queue_pair *queue)
{
    int cpu;
    __u16  cmd_id;
    struct nap_io_request *req;

#ifdef NAP_PER_CPU_IO_REQ_ALLICATION
    /**
     * 试一下固定分配8个queue，每一个CPU对应一个queue
     * 感觉这样性能更好....
     */
    cpu = smp_processor_id();
    cmd_id = atomic_fetch_add(1, this_cpu_ptr(&cpu_cmd_id));
    cmd_id = cmd_id % (queue->q_depth / num_possible_cpus());

    // Calculate the actual command ID in the queue's request array
    cmd_id = (cpu * (queue->q_depth / num_possible_cpus())) + cmd_id;
    if (cmd_id >= queue->q_depth)
        cmd_id = cpu % queue->q_depth; // Fallback
#else
    cmd_id = atomic_fetch_add(1, &queue->cmd_id);
    cmd_id = cmd_id % queue->q_depth;
#endif

    req = &queue->reqs[cmd_id];

    // prefetchw(req);
    while (req->status != IO_INIT) {
        cpu_relax();
    }

    WRITE_ONCE(req->status, IO_RESERVED);
    req->cmd_id = cmd_id;
    req->qidx = queue->qidx;
    req->dma_ctx = NULL;
    req->prp_list = NULL;
#ifdef NAP_USE_NAP_POLL
    req->complete_type = queue->io_complete_type;
#endif
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP
    // req->submit_time = ktime_get();
    // req->nr_check = 0;
    // req->max_check_time = 0;
    req->complete_reponse_time = 0;
#endif
#ifdef NAP_DEBUG_CACHE_TEST
    req->cache_test = 0;
#endif
    // DMA is null
#ifdef NAP_PER_CPU_IO_REQ_ALLICATION
    __this_cpu_write(current_req, req);
#endif
    return req;
}

void free_io_request(struct nap_io_request *req)
{
    // shall me need a barrier here?
    memset(req, 0, sizeof(struct nap_io_request));
    // req->status = IO_INIT;
    WRITE_ONCE(req->status, IO_INIT);
}

static void request_setup_prp(struct nap_ns *ns_entry, struct nap_io_request *req)
{
    int i;
    __le64 *prp_list;
    dma_addr_t prp_dma;
    int nr_pages = req->dma_ctx->nr_dma_pages;
#ifdef NAP_DEBUG_NVME_SETUP_COST
    ktime_t kt_start, kt_end;
    kt_start = ktime_get();
#endif
    if(unlikely(nr_pages == 0)) {
        BUG();
    }

    // setup prp configuration...
    req->prp1 = req->dma_ctx->dma_addrs[0].phys_addr;
    if(nr_pages == 1) {
        req->prp2 = 0;   
    } else if(nr_pages == 2) {
        req->prp2 = req->dma_ctx->dma_addrs[1].phys_addr;
    } else {
        // req->prp2 = req->dma_ctx->dma_addrs[1].phys_addr;
        struct dma_pool *pool = ns_entry->nap_dev_entry->prp_dma_pool;
        if(nr_pages >= 512) {
            nap_err_log("The existing implementation only supports the buffer size less than 2MB\n");
            BUG();
        }
        prp_list = dma_pool_alloc(pool, GFP_ATOMIC, &prp_dma);
        if(!prp_list) {
            nap_err_log("Error on allocating prp list\n");
            BUG();
        }
        for (i = 1; i < nr_pages; i++) {
            prp_list[i - 1] = cpu_to_le64(req->dma_ctx->dma_addrs[i].phys_addr); //cpu_to_le64(req->dma_ctx->dma_addrs[i].phys_addr);
            // nap_info_log("prp_dma = %lu, prplist[%d] = %lu\n", prp_dma, i - 1, req->dma_ctx->dma_addrs[i].phys_addr);
        }
        req->prp2 = prp_dma;
        req->prp_list = prp_list;
    } 
#ifdef NAP_DEBUG_DMA_MAPPING_TYPE_TRACE
    dma_map_type_cnt[req->dma_ctx->mapped]++;
    if(nr_pages == 1) {
        dma_map_type_prp_cnt[0] += nr_pages;
    } else if(nr_pages == 2) {
        dma_map_type_prp_cnt[1] += nr_pages;
    } else {
        dma_map_type_prp_cnt[2] += nr_pages;
    } 
#endif
#ifdef NAP_DEBUG_NVME_SETUP_COST
    kt_end = ktime_get();
    nap_debug_nvme_setup_prp_lat += ktime_to_ns(ktime_sub(kt_end, kt_start));
    nap_debug_nvme_setup_prp_lat_cnt++;
#endif
}

static inline void request_setup_cmd(struct nap_queue_pair *queue, struct nap_io_request *req, struct nvme_rw_command *cmd, uint8_t opcode, unsigned long slba, size_t bufsize)
{
#ifdef NAP_DEBUG_NVME_SETUP_COST
    ktime_t kt_start, kt_end;
    kt_start = ktime_get();
#endif
    // setup nvme command
    cmd->opcode = opcode;
    cmd->command_id = req->cmd_id;
    cmd->nsid = cpu_to_le32(queue->ns_entry->ns->head->ns_id);
    cmd->dptr.prp1 = cpu_to_le64(req->prp1);
    cmd->dptr.prp2 = cpu_to_le64(req->prp2);
    cmd->slba = cpu_to_le64(queue->ns_entry->start_sect + slba);
    cmd->length = cpu_to_le16((SECTOR_ALIGN(bufsize) >> queue->ns_entry->ns->lba_shift) - 1);
    cmd->control = 0;
    cmd->dsmgmt = 0;
#ifdef NAP_DEBUG_NVME_SETUP_COST
    kt_end = ktime_get();
    nap_debug_nvme_setup_cmd_lat += ktime_to_ns(ktime_sub(kt_end, kt_start));
    nap_debug_nvme_setup_cmd_lat_cnt++;
#endif
    // nap_info_log("opcode = %d, bufsize = %d, llength = %d, lba_shift = %d, slba = %lu, prp1 = %lu, prp2 = %lu\n", 
    //     cmd->opcode, bufsize, cmd->length, queue->ns_entry->ns->lba_shift, cmd->slba, req->prp1, req->prp2);
}


// refer to nvme_submit_cmd funtion and nvme_write_sq_db in pci.c
// for completion, please refer to nvme_ring_cq_doorbell in pci.c
static inline void nvme_submit_cmd(struct nap_queue_pair *queue, struct nvme_rw_command *cmd)
{
    struct nvme_queue *nvmeq = queue->nvmeq;
#ifdef NAP_DEBUG_NVME_SETUP_COST
    ktime_t kt_start, kt_end;
    kt_start = ktime_get();
#endif
    spin_lock(&queue->sq_lock);
    memcpy(nvmeq->sq_cmds + (nvmeq->sq_tail << nvmeq->sqes), cmd, sizeof(*cmd));
    if (++nvmeq->sq_tail == nvmeq->q_depth)
        nvmeq->sq_tail = 0;
    writel(nvmeq->sq_tail, nvmeq->q_db);
    spin_unlock(&queue->sq_lock);
#ifdef NAP_DEBUG_NVME_SETUP_COST
    kt_end = ktime_get();
    nap_debug_nvme_submit_cmd_lat += ktime_to_ns(ktime_sub(kt_end, kt_start));
    nap_debug_nvme_submit_cmd_lat_cnt++;
#endif
}

void nap_nvme_submit_io_request(struct nap_queue_pair *queue, struct nap_io_request *req, uint8_t opcode, unsigned long slba)
{
    struct nvme_rw_command cmnd;
#ifdef NAP_DEBUG_QUEUE_IDX_TRACE
    queue_idx_io_cnt[queue->qidx]++;
#endif
    req->opcode = opcode;
    request_setup_prp(queue->ns_entry, req);
    request_setup_cmd(queue, req, &cmnd, opcode, slba, req->dma_ctx->ubuf_len);
    nvme_submit_cmd(queue, &cmnd);
}


static inline bool nvme_cqe_pending(struct nap_queue_pair *queue)
{
    struct nvme_queue *nvmeq = queue->nvmeq;
    struct nvme_completion *hcqe = &nvmeq->cqes[nvmeq->cq_head];
    return (le16_to_cpu(READ_ONCE(hcqe->status)) & 1) == nvmeq->cq_phase;
}

static inline void nvme_update_cq_head(struct nap_queue_pair *queue)
{
    struct nvme_queue *nvmeq = queue->nvmeq;
	u32 tmp = nvmeq->cq_head + 1;

	if (tmp == nvmeq->q_depth) {
		nvmeq->cq_head = 0;
		nvmeq->cq_phase ^= 1;
	} else {
		nvmeq->cq_head = tmp;
	}
}

static inline void nvme_ring_cq_doorbell(struct nap_queue_pair *queue)
{
	struct nvme_queue *nvmeq = queue->nvmeq;
    u16 head = nvmeq->cq_head;
	writel(head, nvmeq->q_db + nvmeq->dev->db_stride);
}

static inline void complete_io(struct nap_ns *ns_entry, struct nap_queue_pair *queue, struct nap_io_request *req)
{
    int nr_running;
#ifdef NAP_DEBUG_UPDATE_TAG_OVERHEAD
    ktime_t start_time, end_time;
    start_time = ktime_get();
#endif
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP
    req->complete_time = ktime_get();
#endif
#ifdef NAP_DEBUG_CACHE_TEST
    req->cache_test = 1;
    req->cache_test_time = ktime_get();
#endif
    nap_debug_log("complete io, cmd id = %d\n", req->cmd_id);
    if(unlikely(req->prp_list)) {
        struct dma_pool *pool = ns_entry->nap_dev_entry->prp_dma_pool;
        dma_pool_free(pool, req->prp_list, req->prp2);
    }
#ifdef NAP_USE_NAP_POLL
    if(likely(req->task != NULL)) {
        if(req->complete_type == IOCT_NAP_POLL) {
            nap_update_complete_sched_state(req->task, 1);
        }
        nr_running = nr_running_tasks(req->task);
        if(nr_running <= 1) {
            req->complete_type = IOCT_POLL;
        } else {
            req->complete_type = IOCT_NAP_POLL;
        }
    } else {
        nap_err_log("Error on complete io, task is NULL, req->cmd_id = %d\n", req->cmd_id);
    }
#endif
#ifdef NAP_DEBUG_IOCT_CNT
    if(req->complete_type == IOCT_POLL) {
        avg_per_ioct_poll++;
    } else if(req->complete_type == IOCT_NAP_YIELD) {
        avg_per_ioct_yield++;
    } else if(req->complete_type == IOCT_NAP_POLL) {
        avg_per_ioct_nap++;
    }
    avg_nr_running += nr_running;
    avg_nr_running_cnt++;
#endif
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP
    // req->complete_time = ktime_get();
    req->complete_reponse_time = 1;
    // avg_per_io_time += ktime_to_us(ktime_sub(req->complete_time, req->submit_time));
    // avg_per_io_time_cnt++;
    // if(ktime_to_us(ktime_sub(req->complete_time, req->submit_time)) > max_per_io_time) {
    //     max_per_io_time = ktime_to_us(ktime_sub(req->complete_time, req->submit_time));
    // }
    // if(ktime_to_us(ktime_sub(req->complete_time, req->submit_time)) < min_per_io_time) {
    //     min_per_io_time = ktime_to_us(ktime_sub(req->complete_time, req->submit_time));
    // }

#ifdef NAP_DEBUG_PER_IO_TIMESTAMP_REPONSE_TIME
    avg_per_io_nr_check += req->nr_check;
    avg_per_io_nr_check_cnt++;
    if(req->nr_check > max_per_io_nr_check) {
        max_per_io_nr_check = req->nr_check;
    }
    if(req->nr_check < min_per_io_nr_check) {
        min_per_io_nr_check = req->nr_check;
    }

    avg_per_io_max_check_time += req->max_check_time;
    avg_per_io_max_check_time_cnt++;
    if(req->max_check_time > max_per_io_max_check_time) {
        max_per_io_max_check_time = req->max_check_time;
    }
    if(req->max_check_time < min_per_io_max_check_time) {
        min_per_io_max_check_time = req->max_check_time;
    }
#endif
#endif
    /**
     * we need to update scheduler flag first then set I/O compelte, to avoid: 
     * if we set I/O complete first, 
     *             --> client  --> i/o completed --> skip out loop --> free_io_request --> free task pointer
     *             --> then update task_wn_status --> task pointer is NULL
     */
    smp_wmb();
    WRITE_ONCE(req->status, IO_COMPLETE);
#ifdef NAP_DEBUG_UPDATE_TAG_OVERHEAD
    end_time = ktime_get();
    nap_debug_nvme_complete_update += ktime_to_ns(ktime_sub(end_time, start_time));
    nap_debug_nvme_complete_update_cnt++;
#endif
}

#ifdef NAP_USE_NAP_POLL
void nvme_nap_poll(struct nap_queue_pair *queue, __u16 cmd_id)
{
    struct nap_io_request *req = &queue->reqs[cmd_id];
#ifdef NAP_DEBUG_RETRY_CNT
    unsigned long retry_cnt = 0;
#endif

    if(req->complete_type == IOCT_NAP_POLL) {
#ifdef NAP_DEBUG_UPDATE_TAG_OVERHEAD
        ktime_t start_time, end_time;
        start_time = ktime_get();
#endif
        nap_update_submit_sched_state(req->task, -1);
 #ifdef NAP_DEBUG_UPDATE_TAG_OVERHEAD
        end_time = ktime_get();
        nap_debug_nvme_submit_update += ktime_to_ns(ktime_sub(end_time, start_time));
        nap_debug_nvme_submit_update_cnt++;
#endif
    }

    prefetchw(&req->status);
    while(READ_ONCE(req->status) != IO_COMPLETE) {
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP_REPONSE_TIME
        if(req->nr_check == 0) {
            req->last_check_time = ktime_get();
        } else {
            ktime_t cur_time = ktime_get();
            ktime_t check_time = ktime_sub(cur_time, req->last_check_time);
            if(ktime_to_ns(check_time) > req->max_check_time) {
                req->max_check_time = ktime_to_ns(check_time);
            }
            req->last_check_time = cur_time;
        }
        req->nr_check++;
#endif
#endif
        if(req->complete_type == IOCT_NAP_POLL) {
            cskip_1_io_reserved++; // do not remove this line as it will affect the result
            schedule();
        } else if(req->complete_type == IOCT_POLL) {
            cpu_relax();
        } else {
            do_sched_yield();
        }

#ifdef NAP_DEBUG_RETRY_CNT
        retry_cnt++;
#endif
    }
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP_REPONSE_TIME
    spin_lock(&per_io_timestamp_lock);
    if(req->complete_reponse_time) {
        unsigned long io_complete_time = ktime_to_ns(req->complete_time);
        unsigned long last_check_time = ktime_to_ns(req->last_check_time);
        
        if(io_complete_time < last_check_time) {
            req->complete_reponse_time = last_check_time - io_complete_time;
            avg_per_io_response_time += req->complete_reponse_time;
            avg_per_io_response_time_cnt++;
            if(req->complete_reponse_time > max_per_io_response_time) {
                max_per_io_response_time = req->complete_reponse_time;
            }
            if(req->complete_reponse_time < min_per_io_response_time) {
                min_per_io_response_time = req->complete_reponse_time;
            }
        } else {
            if(last_check_time == 0) {
                last_check_time = ktime_to_ns(req->submit_time);
                printk("cskip = %d\n", req->task->se.cskip);
            }
            req->complete_reponse_time = io_complete_time - last_check_time;
            avg_per_io_response_time2 += req->complete_reponse_time;
            avg_per_io_response_time_cnt2++;
            if(req->complete_reponse_time > max_per_io_response_time2) {
                printk("max_per_io_response_time2 = %lu, req->complete_time = %lu, req->last_check_time = %lu, req->complete_reponse_time = %lu, nr_check = %d\n", max_per_io_response_time2, io_complete_time, last_check_time, req->complete_reponse_time, req->nr_check);
                max_per_io_response_time2 = req->complete_reponse_time;
            }
            if(req->complete_reponse_time < min_per_io_response_time2) {
                min_per_io_response_time2 = req->complete_reponse_time;
            }
        }

    }
    if(req->task->se.cskip != 0) {
        printk("note!! cskip = %d\n", req->task->se.cskip);
    }
    spin_unlock(&per_io_timestamp_lock);
#endif
#endif
#ifdef NAP_DEBUG_CACHE_TEST
    cache_test_cnt += req->cache_test + ktime_to_ns(req->cache_test_time);
#endif
#ifdef NAP_DEBUG_RETRY_CNT
    avg_per_io_retry_cnt += retry_cnt;
    avg_per_io_retry_cnt_cnt++;
#endif
}

int nvme_nap_complete_io(struct nap_queue_pair *queue)
{
    int complete_cnt = 0;
    __u16 start = 0, end = 0, cqe_cmd_id;
    struct nvme_completion *cqe;
    struct nap_ns *ns_entry = queue->ns_entry;
    struct nvme_queue *nvmeq = queue->nvmeq;

    if (!nvme_cqe_pending(queue))
        return 0;

    // prefetchw(&nvmeq->cq_head);

    /**
     * we do not need cq_lock here as we use one dedicated thread to make I/O completed.
     * if we try to support multiple dedicated thread, we must use cq_lock here.
     * or statically assign seperate queues to each thread.
     */
    start = nvmeq->cq_head;
    while (nvme_cqe_pending(queue)) {
        nvme_update_cq_head(queue);
    }
    end = nvmeq->cq_head;

    // Ring doorbell
    if (start != end) {
        nvme_ring_cq_doorbell(queue);
    }

    while (start != end) {
        struct nap_io_request *req;
        cqe = &nvmeq->cqes[start];
        cqe_cmd_id = READ_ONCE(cqe->command_id);
        req = &queue->reqs[cqe_cmd_id];

        // Prefetch the next completion entry
        if (start + 1 != end) {
            __u16 next = (start + 1 == nvmeq->q_depth) ? 0 : start + 1;
            prefetch(&nvmeq->cqes[next]);
        }
        // if(cqe->status & 0x7ff) {
        //     nap_info_log("nvme_poll complete io, cmd id = %d, cqe->sq_head = %d, nvmeq->sq_tail = %d, result = %d, rstatus = %d\n", 
        //         cqe_cmd_id, cqe->sq_head, nvmeq->sq_tail, cqe->result, cqe->status & 0x7ff);
        // }
        complete_io(ns_entry, queue, req);
        if (++start == nvmeq->q_depth) 
            start = 0;

        complete_cnt++;
    }

    return complete_cnt;
}
#else
void nvme_poll(struct nap_queue_pair *queue, __u16 cmd_id)
{
    struct nap_io_request *req;
    volatile struct nvme_completion *cqe;
    struct nap_ns *ns_entry = queue->ns_entry;
    struct nvme_queue *nvmeq = queue->nvmeq;
    __u16 start = 0, end = 0, cqe_cmd_id;
#ifdef NAP_DEBUG_NVME_POLL_OVERHEAD
    ktime_t start_cio_time, end_cio_time;
    unsigned long loop_tries = 0;
#endif
    req = &queue->reqs[cmd_id];
    for(;;) {
#ifdef NAP_DEBUG_NVME_POLL_OVERHEAD
        loop_tries++;
#endif
        if (READ_ONCE(req->status) == IO_COMPLETE) {
            break;
        }

        if (!nvme_cqe_pending(queue)) {
            continue;
        }
#ifdef NAP_DEBUG_NVME_POLL_OVERHEAD
        start_cio_time = ktime_get();
#endif
        if (spin_trylock(&queue->cq_lock) == 1) {
            start = nvmeq->cq_head;
            while (nvme_cqe_pending(queue)) {
                nvme_update_cq_head(queue);
            }
            end = nvmeq->cq_head;

            // dma_rmb();
            // Ring doorbell
            if (start != end) {
                nvme_ring_cq_doorbell(queue);
            }
            spin_unlock(&queue->cq_lock);

            while (start != end) {
                cqe = &nvmeq->cqes[start];
                cqe_cmd_id = READ_ONCE(cqe->command_id);
                // if(cqe->status & 0x7ff) {
                //     nap_info_log("nvme_poll complete io, cmd id = %d, cqe->sq_head = %d, nvmeq->sq_tail = %d, result = %d, rstatus = %d\n", 
                //         cqe_cmd_id, cqe->sq_head, nvmeq->sq_tail, cqe->result, cqe->status & 0x7ff);
                // }
                complete_io(ns_entry, queue, &queue->reqs[cqe_cmd_id]);
                if (++start == nvmeq->q_depth) 
                    start = 0;
            }
            start = end = 0;
        }
        // cpu_relax(); // is this an optimization?
#ifdef NAP_DEBUG_NVME_POLL_OVERHEAD
        end_cio_time = ktime_get();
        avg_per_io_complete_time += ktime_to_ns(ktime_sub(end_cio_time, start_cio_time));
        avg_per_io_complete_cnt++;
#endif
    }
#ifdef NAP_DEBUG_NVME_POLL_OVERHEAD
    avg_per_io_loop_tries += loop_tries;
    avg_per_io_loop_tries_cnt++;
#endif
}
#endif

static void print_nap_request_debug_info(void)
{
    int i;
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP
    if(avg_per_io_time_cnt > 0)
        nap_info_log("avg per io time = %lu us, min per io time = %lu, max per io time = %lu\n", avg_per_io_time / avg_per_io_time_cnt, min_per_io_time, max_per_io_time);
    if(avg_per_io_nr_check_cnt > 0)
        nap_info_log("avg per io nr check = %lu, min per io nr check = %lu, max per io nr check = %lu\n", avg_per_io_nr_check / avg_per_io_nr_check_cnt, min_per_io_nr_check, max_per_io_nr_check);
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP_REPONSE_TIME
    if(avg_per_io_max_check_time_cnt > 0)
        nap_info_log("avg per io max check time = %lu ns, min per io max check time = %lu, max per io max check time = %lu\n", avg_per_io_max_check_time / avg_per_io_max_check_time_cnt, min_per_io_max_check_time, max_per_io_max_check_time);
    if(avg_per_io_response_time_cnt > 0)
        nap_info_log("avg per io response time = %lu ns, min per io response time = %lu, max per io response time = %lu, complete_then_check = %lu\n", avg_per_io_response_time / avg_per_io_response_time_cnt, min_per_io_response_time, max_per_io_response_time, avg_per_io_response_time_cnt);
    if(avg_per_io_response_time_cnt2 > 0)
        nap_info_log("avg per io response time2 = %lu ns, min per io response time2 = %lu, max per io response time2 = %lu, check_then_complete = %lu\n", avg_per_io_response_time2 / avg_per_io_response_time_cnt2, min_per_io_response_time2, max_per_io_response_time2, avg_per_io_response_time_cnt2);
#endif
#endif
#ifdef NAP_DEBUG_CACHE_TEST
    nap_info_log("cache test cnt = %lu\n", cache_test_cnt);
#endif
#ifdef NAP_DEBUG_NVME_POLL_OVERHEAD
    if(avg_per_io_complete_cnt > 0)
        nap_info_log("avg per io complete time = %ld ns\n", avg_per_io_complete_time / avg_per_io_complete_cnt);
    if(avg_per_io_loop_tries_cnt > 0)
        nap_info_log("avg per io loop tries = %ld\n", avg_per_io_loop_tries / avg_per_io_loop_tries_cnt);
#endif
#ifdef NAP_DEBUG_QUEUE_IDX_TRACE
    for(i = 0; i < MAX_USER_QUEUES; i++) {
        if(queue_idx_io_cnt[i] != 0)
            nap_info_log("queue idx = %d, io cnt = %ld\n", i, queue_idx_io_cnt[i]);
    }
#endif
#ifdef NAP_DEBUG_DMA_MAPPING_TYPE_TRACE
    for(i = 0; i < 5; i++) {
        if(dma_map_type_cnt[i] != 0)
            nap_info_log("dma map type = %d, cnt = %ld\n", i, dma_map_type_cnt[i]);
    }
    for(i = 0; i < 5; i++) {
        if(dma_map_type_prp_cnt[i] != 0)
            nap_info_log("dma map type prp = %d, cnt = %ld\n", i, dma_map_type_prp_cnt[i]);
    }
#endif
#ifdef NAP_DEBUG_RETRY_CNT
    if(avg_per_io_retry_cnt_cnt > 0)
        nap_info_log("avg per io retry cnt = %ld\n", avg_per_io_retry_cnt / avg_per_io_retry_cnt_cnt);
#endif
#ifdef NAP_DEBUG_IOCT_CNT
    if(avg_nr_running_cnt > 0)
        nap_info_log("avg per ioct poll = %ld, yield = %ld, nap = %ld, nr_running = %d\n", 
            avg_per_ioct_poll, avg_per_ioct_yield, avg_per_ioct_nap, avg_nr_running / avg_nr_running_cnt);
#endif
#ifdef NAP_DEBUG_IO_THREAD_CPU_CHANGE_CNT
    for(i = 0; i < 100; i++) {
        if(io_thread_wake_affine_cpu_dist_cnt[i] != 0)
            nap_info_log("io thread wake affine cpu dist, cpu = %d, cnt = %ld\n", i, io_thread_wake_affine_cpu_dist_cnt[i]);
    }
#endif
#ifdef NAP_DEBUG_NVME_SETUP_COST
    if(nap_debug_nvme_setup_prp_lat_cnt > 0)
        nap_info_log("avg per io setup prp lat = %ld ns\n", nap_debug_nvme_setup_prp_lat / nap_debug_nvme_setup_prp_lat_cnt);
    if(nap_debug_nvme_setup_cmd_lat_cnt > 0)
        nap_info_log("avg per io setup cmd lat = %ld ns\n", nap_debug_nvme_setup_cmd_lat / nap_debug_nvme_setup_cmd_lat_cnt);
    if(nap_debug_nvme_submit_cmd_lat_cnt > 0)
        nap_info_log("avg per io submit cmd lat = %ld ns\n", nap_debug_nvme_submit_cmd_lat / nap_debug_nvme_submit_cmd_lat_cnt);
#endif
#ifdef NAP_DEBUG_UPDATE_TAG_OVERHEAD
    if(nap_debug_nvme_complete_update_cnt > 0)
        nap_info_log("avg per io complete update lat = %ld ns\n", nap_debug_nvme_complete_update / nap_debug_nvme_complete_update_cnt);
    if(nap_debug_nvme_submit_update_cnt > 0)
        nap_info_log("avg per io submit update lat = %ld ns\n", nap_debug_nvme_submit_update / nap_debug_nvme_submit_update_cnt);
    nap_info_log("nap_nvme_request size = %lu, nvme queue pari size = %lu\n", sizeof(struct nap_io_request), sizeof(struct nap_queue_pair));
#endif
}

int init_nvme_request_settings(struct nap_dev *nap_dev)
{
    int cpu;
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP
#ifdef NAP_DEBUG_PER_IO_TIMESTAMP_REPONSE_TIME
    spin_lock_init(&per_io_timestamp_lock);
#endif
#endif
#ifdef NAP_PER_CPU_IO_REQ_ALLICATION
    // Initialize per-CPU command IDs
    for_each_possible_cpu(cpu) {
        atomic_set(per_cpu_ptr(&cpu_cmd_id, cpu), 0);
        *per_cpu_ptr(&current_req, cpu) = NULL;
    }
#endif
    return 0;
}

void exit_nvme_request_settings(void)
{
    print_nap_request_debug_info();
}
