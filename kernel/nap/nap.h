#ifndef LINUX_NAP_H
#define LINUX_NAP_H
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include "linux-export.h"

////////////////////////////////////////////////// debug flags
// #define NAP_DEBUG_LOG
// #define NAP_DEBUG_SUBMIT_COST
// #define NAP_DEBUG_SUBMIT_DMA_COST
// #define NAP_DEBUG_RETRY_CNT
// #define NAP_DEBUG_IOCT_CNT
// #define NAP_DEBUG_QUEUE_IDX_TRACE
// #define NAP_DEBUG_DMA_MAPPING_TYPE_TRACE
// #define NAP_DEBUG_NVME_POLL_OVERHEAD
// #define NAP_DEBUG_NAP_POLL_NOTIFY_OVERHEAD
// #define NAP_DEBUG_NAP_IO_COMPLETE_THREAD
// #define NAP_DEBUG_CACHE_TEST
// #define NAP_DEBUG_IO_THREAD_CPU_CHANGE_CNT
// #define NAP_DEBUG_UPDATE_TAG_OVERHEAD
// #define NAP_DEBUG_NAP_MAP_OVERHEAD


// This debug flag is used to check the time cost of nvme request
// #define NAP_DEBUG_NVME_SETUP_COST

// #define NAP_DEBUG_PER_IO_TIMESTAMP
// #ifdef NAP_DEBUG_PER_IO_TIMESTAMP
// #define NAP_DEBUG_PER_IO_TIMESTAMP_REPONSE_TIME
// #endif

//////////////////////////////////////////////////
#define NAP_PER_CPU_IO_REQ_ALLICATION
// #define NAP_USE_NAP_POLL

#define nap_info_log(fmt, ...) \
	do{printk(KERN_INFO "[NAP-INFO]:(%s):%d: " fmt, __func__, __LINE__, ##__VA_ARGS__);} while(0)

#define nap_err_log(fmt, ...) \
	do{printk(KERN_ERR "[NAP-ERR]:(%s):%d: " fmt, __func__, __LINE__, ##__VA_ARGS__);} while(0)

#ifdef NAP_DEBUG_LOG
#define nap_debug_log(fmt, ...) \
	do{printk(KERN_DEBUG "[NAP-DBG][PID=%d]:(%s):%d: " fmt, current->pid, __func__, __LINE__, ##__VA_ARGS__);} while(0)
#else
#define nap_debug_log(fmt, ...) \
	do{} while(0)
#endif

#define SQ_SIZE(len) (len * sizeof(struct nvme_command))
#define CQ_SIZE(len) (len * sizeof(struct nvme_completion))

#define MAX_USER_QUEUES 128
#define MAX_PER_BIO_PAGES 32

struct nap_dev {
    struct nvme_dev *ndev;
    struct pci_dev *pdev;

    struct rw_semaphore ctrl_lock;

    unsigned int num_user_queue;
    unsigned int max_user_queues;
    DECLARE_BITMAP(queue_bmap, 65536);

    struct dma_pool *prp_dma_pool;
    struct list_head list;
    struct list_head ns_list;
};

struct nap_io_queue_ctx;

struct nap_ns {
    struct nap_dev *nap_dev_entry;

    struct nvme_ns *ns;
    unsigned int start_sect;

    struct proc_dir_entry *ns_proc_root;
    struct proc_dir_entry *ns_proc_ioctl;

    struct task_struct *io_complete_task;
    struct nap_io_queue_ctx *nap_io_queues;

    struct list_head list;
    struct list_head queue_list;
};

struct nap_ns_info {
    unsigned int ns_id;
    unsigned int lba_start;
    int lba_shift;
};

struct nap_rw_cmd {
    int fd;
    int rw;
    int queue_idx;
    unsigned int len;
    unsigned long lba;
    unsigned long ofs;
    unsigned long vaddr; // user buffer vaddr
};

struct nap_dma_addr {
    unsigned long phys_addr;
};

struct nap_dma_addr_ctx {
    struct nap_ns *ns_entry;
    int mapped; // 0: not mapped, 1: mapped by fast way, 2: mapped by slow way
    int dma_cache_buffer_pos;
    unsigned long ubuf_addr;
    unsigned int ubuf_len;
    unsigned long offset;
    unsigned int nr_dma_pages;
    unsigned int dma_addr_ofs;
    struct nap_dma_addr *dma_addrs;
    struct page **pages;
};

struct nap_io_request {
    
    __u8 status;
    __u16   complete_type;
    __u8    opcode; // 
    __u16   cmd_id;
    __u32   qidx;

    __u64   prp1;
    __u64   prp2;
    __le64  *prp_list;
    struct nap_dma_addr_ctx *dma_ctx;
    struct task_struct *task;

#ifdef NAP_DEBUG_PER_IO_TIMESTAMP
    // ktime_t submit_time;
    // ktime_t last_check_time;
    // unsigned long max_check_time;
    // __u32   nr_check;
    ktime_t complete_time;
    unsigned long complete_reponse_time;
#endif

#ifdef NAP_DEBUG_CACHE_TEST
    ktime_t cache_test_time;
    unsigned long cache_test;
#endif
} ____cacheline_aligned_in_smp;

struct nap_queue_pair {
    struct nap_ns *ns_entry;
    struct nvme_queue *nvmeq;
    unsigned short qid;
    unsigned short qidx;
    int q_depth;
    int db_stride;
    int io_complete_type;

    // for ssd settings
    // struct nap_ns_info ns_info; // read only between I/O threads and the I/O completion thread

    // for io request
    atomic_t   cmd_id;

    spinlock_t sq_lock;
    spinlock_t cq_lock;

    struct nap_io_request *reqs;
} ____cacheline_aligned_in_smp;

struct nap_io_queue_ctx {
    int intilized;
    int nr_queues;
    struct nap_queue_pair *io_queues;
};

struct nap_reg {
    int queue_idx;
};

#define NAP_IOC_MAGIC  0x46
#define NAP_IOC_DEBUG_READ _IOW(NAP_IOC_MAGIC, 1, struct nap_rw_cmd)
#define NAP_IOC_ENABLE _IOW(NAP_IOC_MAGIC, 2, long)
#define NAP_IOC_DISABLE _IOW(NAP_IOC_MAGIC, 3, long)
#define NAP_IOC_SUBMIT_IO _IOW(NAP_IOC_MAGIC, 4, struct nap_rw_cmd)
#define NAP_IOC_REGISTER_FILE _IOW(NAP_IOC_MAGIC, 5, struct nap_reg)
#define NAP_IOC_UNREGISTER_FILE _IOW(NAP_IOC_MAGIC, 6, struct nap_reg)
#define NAP_IOC_SET_FLAG _IOW(NAP_IOC_MAGIC, 7, unsigned long)


#ifndef NAP_KERNEL_VER_6
static inline void mmap_read_lock(struct mm_struct *mm)
{
    down_read(&mm->mmap_sem);
}

static inline void mmap_read_unlock(struct mm_struct *mm)
{
    up_read(&mm->mmap_sem);
}

static inline void *pde_data(const struct inode *inode)
{
	return PDE_DATA(inode);
}
#endif

#endif