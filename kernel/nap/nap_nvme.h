#ifndef LINUX_NAP_NVME_H
#define LINUX_NAP_NVME_H
#include <linux/proc_fs.h>
#include "nap.h"

enum {
    IO_INIT = 0,
    IO_RESERVED = 1,
    IO_COMPLETE = 2,
    IO_ERROR = 3,
};

// I/O complete type (IOCT)
enum {
    IOCT_POLL = 0,
    IOCT_NAP_YIELD = 1,
    IOCT_NAP_POLL = 2,
};

#ifdef NAP_KERNEL_VER_6
int init_nvme_devices(struct proc_dir_entry *nap_proc_root, const struct proc_ops *proc_fops);
#else
int init_nvme_devices(struct proc_dir_entry *nap_proc_root, const struct file_operations *proc_fops);
#endif
void free_nvme_devices(void);

int nap_init_io_queues(struct nap_ns *ns_entry, int nr_queues);
int nap_release_io_queues(struct nap_ns *ns_entry);
struct nap_queue_pair *get_io_queue_by_qidx(struct nap_ns *ns_entry, int qidx);
int get_qidx(struct nap_ns *ns_entry);

struct nap_io_request *alloc_io_request(struct nap_queue_pair *queue);
void free_io_request(struct nap_io_request *req);
void nap_nvme_submit_io_request(struct nap_queue_pair *queue, struct nap_io_request *req, uint8_t opcode, unsigned long slba);
#ifdef NAP_USE_NAP_POLL
void nvme_nap_poll(struct nap_queue_pair *queue, __u16 cmd_id);
int nvme_nap_complete_io(struct nap_queue_pair *queue);
#else
void nvme_poll(struct nap_queue_pair *queue, __u16 cmd_id);
#endif

int init_nvme_request_settings(struct nap_dev *nap_dev);
void exit_nvme_request_settings(void);
#endif