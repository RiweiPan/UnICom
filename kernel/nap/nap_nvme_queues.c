#include "nap_nvme.h"

static int alloc_cq(struct nap_dev *dev_entry, u16 qid, struct nvme_queue *nvmeq)
{
    struct nvme_dev *ndev = dev_entry->ndev;
    struct nvme_command c;
    int flags = NVME_QUEUE_PHYS_CONTIG;

    /*
     * Note: we (ab)use the fact the the prp fields survive if no data
     * is attached to the request.
     */
    memset(&c, 0, sizeof(c));
    c.create_cq.opcode     = nvme_admin_create_cq;
    c.create_cq.prp1       = cpu_to_le64(nvmeq->cq_dma_addr);
    c.create_cq.cqid       = cpu_to_le16(qid);
    c.create_cq.qsize      = cpu_to_le16(nvmeq->q_depth - 1);
    c.create_cq.cq_flags   = cpu_to_le16(flags);
    c.create_cq.irq_vector = 0;
    printk("[alloc_cq]: qid = %d\n", qid);
    return nvme_submit_sync_cmd(ndev->ctrl.admin_q, &c, NULL, 0);
}

static int alloc_sq(struct nap_dev *dev_entry, u16 qid, struct nvme_queue *nvmeq) 
{
    struct nvme_dev *ndev = dev_entry->ndev;
    struct nvme_command c;
    int flags = NVME_QUEUE_PHYS_CONTIG;

    memset(&c, 0, sizeof(c));
    c.create_sq.opcode   = nvme_admin_create_sq;
    c.create_sq.prp1     = cpu_to_le64(nvmeq->sq_dma_addr);
    c.create_sq.sqid     = cpu_to_le16(qid);
    c.create_sq.qsize    = cpu_to_le16(nvmeq->q_depth - 1);
    c.create_sq.sq_flags = cpu_to_le16(flags);
    c.create_sq.cqid     = cpu_to_le16(qid);

    return nvme_submit_sync_cmd(ndev->ctrl.admin_q, &c, NULL, 0);
}

static int delete_queue(struct nap_dev *dev_entry, u8 opcode, u16 qid)
{
    struct nvme_dev *ndev = dev_entry->ndev;
    struct nvme_command c;

    memset(&c, 0, sizeof(c));
    c.delete_queue.opcode = opcode;
    c.delete_queue.qid    = cpu_to_le16(qid);

    return nvme_submit_sync_cmd(ndev->ctrl.admin_q, &c, NULL, 0);
}

static struct nvme_queue *nap_alloc_nvmeq(struct nap_dev *dev_entry, int qid, int depth)
{
    struct nvme_dev   *ndev = dev_entry->ndev;
    struct nvme_queue *nvmeq;
    int ret;

    nvmeq = kzalloc(sizeof(*nvmeq), GFP_KERNEL);
    if(!nvmeq) return NULL;

    nvmeq->sqes    = 6;
    nvmeq->q_depth = depth;
    nvmeq->dev     = ndev;
    // Allocate DMA memory for CQ
    nvmeq->cqes    = dma_alloc_coherent(&dev_entry->pdev->dev, CQ_SIZE(depth),
                            &nvmeq->cq_dma_addr, GFP_KERNEL);
    if(!nvmeq->cqes) {
        nap_err_log("No memory for CQ allocation\n");
        ret = -ENOMEM;
        goto free_nvmeq;
    }

    // Allocate DMA memory for SQ
    nvmeq->sq_cmds = dma_alloc_coherent(&dev_entry->pdev->dev, SQ_SIZE(depth),
                            &nvmeq->sq_dma_addr, GFP_KERNEL);
    if(!nvmeq->sq_cmds) {
        nap_err_log("No memory for SQ allocation\n");
        ret = -ENOMEM;
        goto free_cqdma;
    }

    // TODO: Currently 4K alloated for db. Each db entry is 4 bytes
    //       Therefore 1K queues can be created. To create more than
    //       1K, need to remap bar by calling nvme_remap_bar()
    nvmeq->dev = ndev;
    spin_lock_init(&nvmeq->sq_lock);
    spin_lock_init(&nvmeq->cq_poll_lock);
    nvmeq->cq_head  = 0;
    nvmeq->cq_phase = 1;
    nvmeq->q_db     = &ndev->dbs[qid * 2 * ndev->db_stride];
    nvmeq->qid      = qid;

    // Register CQ with device
    ret = alloc_cq(dev_entry, qid, nvmeq);
    if (ret != 0) {
        nap_err_log("Alloc CQ failed %d\n", ret & 0x7ff);
        ret = -ENOSPC;
        goto free_sqdma;
    }

    // Register SQ with device
    ret = alloc_sq(dev_entry, qid, nvmeq);
    if (ret != 0) {
        nap_err_log("Alloc SQ failed %d\n", ret);
        delete_queue(dev_entry, nvme_admin_delete_cq, qid);
        goto free_sqdma;
    }

    nvmeq->sq_tail      = 0;
    nvmeq->last_sq_tail = 0;
    memset((void *)nvmeq->cqes, 0, CQ_SIZE(nvmeq->q_depth));
    return nvmeq;

free_sqdma:
    dma_free_coherent(&dev_entry->pdev->dev, SQ_SIZE(depth), (void *)nvmeq->sq_cmds,
                        nvmeq->sq_dma_addr);
free_cqdma:
    dma_free_coherent(&dev_entry->pdev->dev, CQ_SIZE(depth), (void *)nvmeq->cqes,
                        nvmeq->cq_dma_addr);
free_nvmeq:
    kfree(nvmeq);
    return NULL;
}

// 这里的实现可以参考 nvme_alloc_queue 
int nap_init_io_queues(struct nap_ns *ns_entry, int nr_queues)
{
    struct nap_dev *dev_entry = ns_entry->nap_dev_entry;
    int i, real_qid;


    if (nr_queues > dev_entry->max_user_queues)
        nr_queues = dev_entry->max_user_queues;

    ns_entry->nap_io_queues->nr_queues = 0;
    ns_entry->nap_io_queues->io_queues = kzalloc(sizeof(struct nap_queue_pair) * nr_queues, GFP_KERNEL);
    if (!ns_entry->nap_io_queues->io_queues) {
        return -ENOMEM;
    }

    for(i = 0; i < nr_queues; i++) {
        struct nap_queue_pair *queue_pair = &ns_entry->nap_io_queues->io_queues[i];

        queue_pair->reqs = kzalloc(sizeof(struct nap_io_request) * dev_entry->ndev->q_depth, GFP_KERNEL);
        if(!queue_pair->reqs) {
            nap_err_log("Error on allocating memory\n");
            break;
        }

        real_qid = find_first_zero_bit(dev_entry->queue_bmap, 256);
        set_bit(real_qid, dev_entry->queue_bmap);
        // nap_info_log("Queue alloc, qidx = %d, qid = %d, queue depth = %d\n", i, real_qid, dev_entry->ndev->q_depth);
        queue_pair->nvmeq = nap_alloc_nvmeq(dev_entry, real_qid, dev_entry->ndev->q_depth);
        if(!queue_pair->nvmeq) {
            nap_err_log("Queue alloc failed, achieve the max queue count = %d\n", i);
            kfree(queue_pair->reqs);
            break;
        }
        nap_debug_log("Queue alloc success, qidx = %d, qid = %d, queue depth = %d\n", i, queue_pair->nvmeq->qid, dev_entry->ndev->q_depth);
        queue_pair->ns_entry = ns_entry;
        queue_pair->qidx = i;
#ifdef NAP_USE_NAP_POLL
        queue_pair->io_complete_type = IOCT_NAP_POLL;
#endif
        queue_pair->qid = real_qid;
        queue_pair->q_depth = dev_entry->ndev->q_depth;
        queue_pair->db_stride = dev_entry->ndev->db_stride;
        atomic_set(&queue_pair->cmd_id, 0);
        spin_lock_init(&queue_pair->sq_lock);
        spin_lock_init(&queue_pair->cq_lock);


        ns_entry->nap_io_queues->nr_queues++;
        dev_entry->num_user_queue++;
    }
    return i;
}

int nap_release_io_queues(struct nap_ns *ns_entry)
{
    int i;
    struct nap_dev *dev_entry = ns_entry->nap_dev_entry;

    if(ns_entry->nap_io_queues->intilized == 0) {
        nap_info_log("The NAP driver is not initialized! Dev Name: nvme%dn%u\n", dev_entry->ndev->ctrl.instance, ns_entry->ns->head->ns_id);
        return 0;
    }

    BUG_ON(ns_entry->nap_io_queues->nr_queues == 0);

    for(i = 0; i <ns_entry->nap_io_queues->nr_queues; i++) {
        struct nap_queue_pair *queue_pair = &ns_entry->nap_io_queues->io_queues[i];
        struct nvme_queue *nvmeq = queue_pair->nvmeq;
        int qid = queue_pair->qid;

        delete_queue(dev_entry, nvme_admin_delete_sq, qid);
        delete_queue(dev_entry, nvme_admin_delete_cq, qid);

        dma_free_coherent(&dev_entry->pdev->dev, SQ_SIZE(nvmeq->q_depth), nvmeq->sq_cmds, nvmeq->sq_dma_addr);
        dma_free_coherent(&dev_entry->pdev->dev, CQ_SIZE(nvmeq->q_depth), (void *)nvmeq->cqes, nvmeq->cq_dma_addr);

        clear_bit(qid, dev_entry->queue_bmap);
        dev_entry->num_user_queue--;
        kfree(nvmeq);
        kfree(queue_pair->reqs);
    }
    kfree(ns_entry->nap_io_queues->io_queues);
    ns_entry->nap_io_queues->nr_queues = 0;
    return 0;
}

struct nap_queue_pair *get_io_queue_by_qidx(struct nap_ns *ns_entry, int qidx)
{
    if(unlikely(qidx >= ns_entry->nap_io_queues->nr_queues)) {
        nap_err_log("Invalid queue index\n");
        return NULL;
    }

    return &ns_entry->nap_io_queues->io_queues[qidx];
}

/** TODO: add dynamic load balancing 
  * 1. when file is opened, we can issue a queue index to this file

  * 2. However, if this file is opened once and its fd is shared by multiple I/O threads,
  * then all I/O threads will use the same queue index, resulting in scalability issue.

  * 3. Why not use a per-core queue index? The paper blk-switch tells us why. Different application's I/Os will be mixed together.
  *   resulting in the head of line blocking.
*/
int get_qidx(struct nap_ns *ns_entry)
{
    int qidx = current->pid % ns_entry->nap_io_queues->nr_queues;
    nap_debug_log("pid = %d qidx = %d\n", current->pid, qidx);
    return qidx;
}
