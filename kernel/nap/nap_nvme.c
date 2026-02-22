#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include "nap_nvme.h"

static LIST_HEAD(nap_dev_list);

static int get_queue_count(struct nap_dev *dev_entry)
{
    int status;
    u32 result = 0;

    status = nvme_get_features(&dev_entry->ndev->ctrl, NVME_FEAT_NUM_QUEUES, 0, NULL, 0, &result);

    if (status < 0) {
        return status;
    } else if (status > 0) {
        dev_err(&dev_entry->pdev->dev, "Could not get queue count (%d)\n", status);
        return 0;
    }
    return min(result & 0xffff, result >> 16) + 1;
}

static inline int set_queue_count(struct nap_dev *dev_entry, int count, int *err)
{
    int status;
    u32 result = 0;
    u32 q_count = (count - 1) | ((count - 1) << 16);

    status = nvme_set_features(&(dev_entry->ndev->ctrl), NVME_FEAT_NUM_QUEUES, q_count, NULL, 0,
                                &result);
    if (status < 0) {
        return status;
    } else if (status > 0) {
        *err = status;
        return 0;
    }
    // when status = 0 and results > 0
    return min(result & 0xffff, result >> 16) + 1;
}

static int nvme_set_max_queue_count(struct nap_dev *dev_entry)
{
    unsigned int queue_count = 0;
    unsigned int max_user_queues = MAX_USER_QUEUES;
    int          result;
    int          err;

    queue_count = dev_entry->ndev->ctrl.queue_count + max_user_queues;
    result      = set_queue_count(dev_entry, queue_count, &err);
    if (result < 0) {
        nap_err_log("Error on set queue count\n");
        return -ENOSPC;
    } else if (result == 0 && err == 6) { //If queue count set to other value
        max_user_queues = get_queue_count(dev_entry);
    } else if(result != max_user_queues) {
        max_user_queues = get_queue_count(dev_entry);
    }
    nap_info_log("max user queue = %d, real queue count = %d, result = %d, err = %d\n", max_user_queues, get_queue_count(dev_entry), result , err);
    return max_user_queues;
}

#ifdef NAP_KERNEL_VER_6
int init_nvme_devices(struct proc_dir_entry *nap_proc_root, const struct proc_ops *proc_fops)
{
    struct nap_dev *dev_entry;
    struct pci_dev *pdev = NULL;
    struct nvme_dev *ndev;
    struct nvme_ns *ns;

    struct nap_ns *ns_entry;
    struct block_device *part;
    unsigned long idx;

    char dev_name[32];
    int  i;

    while ((pdev = pci_get_class(PCI_CLASS_STORAGE_EXPRESS, pdev))) {
        ndev = pci_get_drvdata(pdev);
        if (ndev == NULL)
            continue;

        dev_entry = kzalloc(sizeof(*dev_entry), GFP_KERNEL);
        dev_entry->ndev = ndev;
        dev_entry->pdev = pdev;

        dev_entry->prp_dma_pool = dma_pool_create("nap_prp_dma_pool", &pdev->dev, PAGE_SIZE, PAGE_SIZE, 0);
        if (!dev_entry->prp_dma_pool) {
            nap_err_log("Failed to create prp dma pool for device <nvme%dn%u>\n", ndev->ctrl.instance, ns->head->ns_id);
            kfree(dev_entry);
            continue;
        }

        dev_entry->num_user_queue = 0;
        init_rwsem(&dev_entry->ctrl_lock);
        for(i = 0; i < ndev->ctrl.queue_count; ++i) {
            set_bit(i, dev_entry->queue_bmap);
        }
        nap_info_log("dev support queue count = %d\n", ndev->ctrl.queue_count);
        list_add(&dev_entry->list, &nap_dev_list);
        INIT_LIST_HEAD(&dev_entry->ns_list);

        list_for_each_entry(ns, &ndev->ctrl.namespaces, list) {
            // disk_part_iter_init(&piter, ns->disk, DISK_PITER_INCL_PART0);
            rcu_read_lock();
            xa_for_each(&ns->disk->part_tbl, idx, part) {
                if (!bdev_nr_sectors(part))
                    continue;
                
                ns_entry = kzalloc(sizeof(*ns_entry), GFP_KERNEL);
                ns_entry->nap_dev_entry = dev_entry;
                ns_entry->ns = ns;
                ns_entry->start_sect = part->bd_start_sect;
                ns_entry->nap_io_queues = kzalloc(sizeof(struct nap_io_queue_ctx), GFP_KERNEL);
                ns_entry->nap_io_queues->nr_queues = 0;
                ns_entry->nap_io_queues->intilized = 0;

                if(bdev_is_partition(part))
                    sprintf(dev_name, "nvme%dn%up%u", ndev->ctrl.instance, ns->head->ns_id, part->bd_partno);
                else
                    sprintf(dev_name, "nvme%dn%u", ndev->ctrl.instance, ns->head->ns_id);

                ns_entry->ns_proc_root = proc_mkdir(dev_name, nap_proc_root);
                if(!ns_entry->ns_proc_root) {
                    nap_err_log("Error creating proc directory - %s\n", dev_name);
                    kfree(ns_entry);
                    continue;
                }

                ns_entry->ns_proc_ioctl = proc_create_data("ioctl", S_IRUSR|S_IRGRP|S_IROTH,
                        ns_entry->ns_proc_root, proc_fops, ns_entry);

                if(!ns_entry->ns_proc_ioctl) {
                    nap_err_log("Error creating proc ioctl file - %s\n", dev_name);
                    proc_remove(ns_entry->ns_proc_root);
                    kfree(ns_entry);
                    continue;
                }

                INIT_LIST_HEAD(&ns_entry->queue_list);

                list_add(&ns_entry->list, &dev_entry->ns_list);
            }
            rcu_read_unlock();
        }

        dev_entry->max_user_queues = nvme_set_max_queue_count(dev_entry);
        nap_info_log("dev = %s, dev max user queue = %d\n", dev_name, dev_entry->max_user_queues);
    }
    return 0;
}
#else
int init_nvme_devices(struct proc_dir_entry *nap_proc_root, const struct file_operations *proc_fops)
{
    struct nap_dev *dev_entry;
    struct pci_dev *pdev = NULL;
    struct nvme_dev *ndev;
    struct nvme_ns *ns;

    struct nap_ns *ns_entry;
    struct disk_part_iter piter;
    struct hd_struct *part;

    char dev_name[32];
    int  i;

    while ((pdev = pci_get_class(PCI_CLASS_STORAGE_EXPRESS, pdev))) {
        ndev = pci_get_drvdata(pdev);
        if (ndev == NULL)
            continue;

        dev_entry = kzalloc(sizeof(*dev_entry), GFP_KERNEL);
        dev_entry->ndev = ndev;
        dev_entry->pdev = pdev;

        dev_entry->prp_dma_pool = dma_pool_create("nap_prp_dma_pool", &pdev->dev, PAGE_SIZE, PAGE_SIZE, 0);
        if (!dev_entry->prp_dma_pool) {
            nap_err_log("Failed to create prp dma pool for device <nvme%dn%u>\n", ndev->ctrl.instance, ns->head->ns_id);
            kfree(dev_entry);
            continue;
        }

        dev_entry->num_user_queue = 0;
        init_rwsem(&dev_entry->ctrl_lock);;
        for(i = 0; i < ndev->ctrl.queue_count; ++i) {
            set_bit(i, dev_entry->queue_bmap);
        }
        nap_info_log("dev support queue count = %d\n", ndev->ctrl.queue_count);
        list_add(&dev_entry->list, &nap_dev_list);
        INIT_LIST_HEAD(&dev_entry->ns_list);

        list_for_each_entry(ns, &ndev->ctrl.namespaces, list) {
            disk_part_iter_init(&piter, ns->disk, DISK_PITER_INCL_PART0);
            while ((part = disk_part_iter_next(&piter))) {
                if(part != &ns->disk->part0 && !part->info)
                    continue;

                ns_entry = kzalloc(sizeof(*ns_entry), GFP_KERNEL);
                ns_entry->nap_dev_entry = dev_entry;
                ns_entry->ns = ns;
                ns_entry->start_sect = part->start_sect;
                ns_entry->nap_io_queues = kzalloc(sizeof(struct nap_io_queue_ctx), GFP_KERNEL);
                ns_entry->nap_io_queues->nr_queues = 0;
                ns_entry->nap_io_queues->intilized = 0;

                if(part == &ns->disk->part0)
                    sprintf(dev_name, "nvme%dn%u", ndev->ctrl.instance, ns->head->ns_id);
                else
                    sprintf(dev_name, "nvme%dn%up%u", ndev->ctrl.instance, ns->head->ns_id, part->partno);

                ns_entry->ns_proc_root = proc_mkdir(dev_name, nap_proc_root);
                if(!ns_entry->ns_proc_root) {
                    nap_err_log("Error creating proc directory - %s\n", dev_name);
                    kfree(ns_entry);
                    continue;
                }

                ns_entry->ns_proc_ioctl = proc_create_data("ioctl", S_IRUSR|S_IRGRP|S_IROTH,
                        ns_entry->ns_proc_root, proc_fops, ns_entry);

                if(!ns_entry->ns_proc_ioctl) {
                    nap_err_log("Error creating proc ioctl file - %s\n", dev_name);
                    proc_remove(ns_entry->ns_proc_root);
                    kfree(ns_entry);
                    continue;
                }

                INIT_LIST_HEAD(&ns_entry->queue_list);

                list_add(&ns_entry->list, &dev_entry->ns_list);
            }
            disk_part_iter_exit(&piter);
        }

        dev_entry->max_user_queues = nvme_set_max_queue_count(dev_entry);
        nap_info_log("dev = %s, dev max user queue = %d\n", dev_name, dev_entry->max_user_queues);
    }
    return 0;
}
#endif

void free_nvme_devices(void)
{
    struct nap_dev *dev_entry, *dev_next;
    struct nap_ns *ns_entry, *ns_next;
    list_for_each_entry_safe(dev_entry, dev_next, &nap_dev_list, list) {
        list_for_each_entry_safe(ns_entry, ns_next, &dev_entry->ns_list, list) {
            down_write(&dev_entry->ctrl_lock);
#ifdef NAP_USE_NAP_POLL
            if(ns_entry->io_complete_task) {
                kthread_stop(ns_entry->io_complete_task);
                ns_entry->io_complete_task = NULL;
            }
#endif
            nap_release_io_queues(ns_entry);
            up_write(&dev_entry->ctrl_lock);
            proc_remove(ns_entry->ns_proc_ioctl);
            proc_remove(ns_entry->ns_proc_root);

            list_del(&ns_entry->list);
            kfree(ns_entry->nap_io_queues);
            kfree(ns_entry);
        }
        dma_pool_destroy(dev_entry->prp_dma_pool);
        list_del(&dev_entry->list);
        kfree(dev_entry);
    }
}
