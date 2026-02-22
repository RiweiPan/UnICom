#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <syscall.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include "ulib.h"

int ulib_initialized = 0;
struct ulib_info *userlib_info;
extern struct file_ops *posix_fops;

#ifdef NAP_DEBUG_USER_KERNEL_BREAKDOWN
static unsigned long nap_debug_kernel_ov[50] = {0};
static unsigned long nap_debug_kernel_ov_cnt[50] = {0};
#endif

#ifdef NAP_DEBUG_FMAP_OVERHEAD
static unsigned long nap_debug_fmap_latency = 0;
static unsigned long nap_debug_fmap_latency_cnt = 0;
#endif

static inline unsigned long get_physical_frame_fast(unsigned long *va, unsigned long lblk)
{
	return (va[lblk] & PTE_PFN_MASK) >> PAGE_SHIFT;
}

/**
 * 这里基于offset获得对应的block的lba地址, 注意这个lba地址是基于block的, 不是基于page的
 */
static int file_get_lba(struct ulib_file *fp, size_t len, loff_t offset, unsigned long *lba, loff_t *io_size)
{
    unsigned long slba;
    unsigned long prev_lba, next_lba;
    loff_t size;
#ifdef NAP_DEBUG_FMAP_OVERHEAD
    struct timespec k_start, k_end;
    clock_gettime(CLOCK_MONOTONIC, &k_start);
#endif
    slba = get_physical_frame_fast((void *)fp->fva, offset / PAGE_SIZE);
    if (slba == 0) {
        nap_ulib_log("get_lba failed @ offset:%ld\n", offset);
        return 1;
    }
    // TODO: In real BypassD, we don't need to issue multiple IOs, IOMMU will
    //       translate into multiple LBAs. How to measure performance gain?
    // If read spans across multiple LBAs, issue separate IOs
    if (offset < PAGE_ALIGN(offset) && (loff_t)(offset + len) > PAGE_ALIGN(offset)) {
        // just truncate for unaligend data
        size = PAGE_ALIGN(offset) - offset;
    } else {
        size = (len < LB_SIZE) ? len : LB_SIZE;

        prev_lba = slba;

        // nap_ulib_log("[get lba] --- 1 offset:%ld, len:%ld\n", size, len);
        while (size < (loff_t) len) {
            nap_ulib_log("[get lba] --- 2 offset:%ld, slba:%ld, lba:%ld, size:%ld\n", offset, slba, *lba, size);
            next_lba = get_physical_frame_fast((void *)fp->fva, (offset + size) / PAGE_SIZE);
            if (next_lba == 0) {
                break; // this might be the end of the file
            } else if (next_lba == prev_lba + 1) { // Contiguous blocks
                unsigned long bs = (len - size < LB_SIZE) ? (len - size) : LB_SIZE;
#ifdef FIX_ROCKSDB_ISSUE
                /**
                  * When running RocksDB, when the I/O size >= 128KB, the RocksDB cannot read the file data correctly due to Power Loss Notification in Linux 6.5.1.
                  * But if we split the large I/O into multiple small I/Os, each I/O size is less than 128KB, the RocksDB can read the file data correctly.
                  */
                if(size + bs > 128 * 1024) { // 128KB
                    break;
                }
#endif
                size += bs;
            } else { // Non-contiguous blocks, issue separate IOs
                break;
            }
            prev_lba = next_lba;
        }
    }

    *lba = (slba << 3) + ((offset % PAGE_SIZE) / BLK_SIZE);
    *io_size = size;
    nap_ulib_log("[get lba] offset:%ld, slba:%ld, lba:%ld, size:%ld\n", offset, slba, *lba, size);
    
    // IMPORTANT: We resue the default settings of BypassD [ASPLOS'24]
    // Delay emulating LBA translation latency (PCIe+IOTLB miss)
    // Value should be set based on core frequency
    // For a 3GHz processor, 1800 cycles ~ 600ns
    for (int x=0; x < 1800; x++) {
       asm volatile ("nop;" : : : "memory");
    }
#ifdef NAP_DEBUG_FMAP_OVERHEAD
    // note that this stat is only thread-safe when using one I/O thread.
    // do not use multiple threads to collect fmap latency.
    clock_gettime(CLOCK_MONOTONIC, &k_end);
    nap_debug_fmap_latency += (k_end.tv_sec - k_start.tv_sec) * 1000000000 + (k_end.tv_nsec - k_start.tv_nsec);
    nap_debug_fmap_latency_cnt++;
#endif
    return 0;
}

int nap_close(int fd)
{
    struct ulib_file *fp;
    struct nap_reg reg;

    fp = &userlib_info->ulib_open_files[fd];
    // Syscall 338 unmaps the file from the user address space
    syscall(338, fd, fp->old_fva, fp->fva);

    reg.queue_idx = fp->queue_idx;
    if(reg.queue_idx >= 0) {
        ioctl(userlib_info->nap_drv_fd, NAP_IOC_UNREGISTER_FILE, &reg);
    }

    fp->opened = 0;

    nap_ulib_log("fd=%d\n", fp->fd);
    return 0;
}


int nap_open(const char *filename, int flags, mode_t mode)
{
    int fd;
    struct ulib_file *fp;
    int ret;
    struct stat f_stat;
    unsigned long addr, addr_fast;
    struct nap_reg reg;
    
    ret = stat(filename, &f_stat);
    if (errno == ENOENT && (flags & O_CREAT)) {
        nap_ulib_log("[%s]: File doesn't exist but creating\n", __func__);
        f_stat.st_size = 0;
        goto special_open;
    } else if (ret != 0) {
        nap_ulib_log("[%s]: File %s doesn't exist, ret = %d, flags = %d, errno = %d\n", __func__, filename, ret, flags, errno);
        return ret;
    }

    // Do not open directories
    if (flags & O_DIRECTORY || !S_ISREG(f_stat.st_mode)) {
        nap_ulib_log("[%s]: Not a regular file\n", __func__);
        return -1;
    }

special_open:

    // Syscall 337 is BypassD's fmap() syscall
    fd = syscall(337, -1, filename, flags, mode, &addr, &addr_fast);
    if (fd < 0) {
        nap_ulib_log("[%s]: Special open returned = %d\n", __func__, fd);
        return fd;
    }

#ifdef NAP_DEBUG_CHECK_FMAP
    {
        unsigned long tslba;
        unsigned long nt_tpages = f_stat.st_size / PAGE_SIZE;
        unsigned long tpage_idx = 0;
        unsigned long range_pgidx_start = 0, range_pgidx_end = 0;
        unsigned long range_slba_start = 0, range_slba_end = 0;

        for(tpage_idx = 0; tpage_idx < nt_tpages; tpage_idx++) {
            tslba = get_physical_frame_fast((void *)addr_fast, tpage_idx);
            printf("fmap mapping Page Index: %lu, PBA: %lu \n", tpage_idx, tslba);

            // if(tpage_idx == 0) {
            //     range_slba_start = tslba;
            // } else {
            //     if(tslba != range_slba_end + 1) {
            //         // We have a gap in the mapping
            //         printf("fmap mapping Page Index: %lu, PBA: %lu, Range: [%lu, %lu] \n", tpage_idx, tslba, range_slba_start, range_slba_end);
            //         range_pgidx_start = tpage_idx;
            //         range_slba_start = tslba;
            //     }
            // }


            // toffset += PAGE_SIZE;
        }
    }
#endif

    reg.queue_idx = -1;
    ret = ioctl(userlib_info->nap_drv_fd, NAP_IOC_REGISTER_FILE, &reg);
    if (ret != 0) {
        nap_ulib_log("[%s]: Register file failed\n", __func__);
        syscall(338, fd, addr, addr_fast);
        return ret;
    }

    fp = &userlib_info->ulib_open_files[fd];

    fp->size = f_stat.st_size;
    fp->old_fva = addr; // Old fva is unused since its slower
    fp->fva = addr_fast;
    fp->queue_idx = reg.queue_idx;

    fp->fd = fd;
    fp->ino = f_stat.st_ino;
    fp->offset = 0;
    fp->flags  = flags;
    fp->mode   = mode;
    fp->append_offset = f_stat.st_size;

    fp->data_modified = false;
    fp->metadata_modified = (flags & O_CREAT) ? true : false;

    fp->opened = 1; // File is now open to access by shim library

    // printf("filename:%s fd:%d fva:0x%lx\n, queue idx = %d\n", filename, fd, fp->fva, fp->queue_idx);
    return fd;
}

ssize_t nap_pread(int fd, void *buf, size_t len, off_t offset)
{
    size_t file_size;
    unsigned long slba = 0;
    loff_t cnt, io_size = 0;
    ssize_t bytes_read = 0, total_bytes_read = 0;
    ssize_t ret;
    struct nap_rw_cmd cmd;
    struct ulib_file *fp = &userlib_info->ulib_open_files[fd];
#ifdef NAP_DEBUG_USER_KERNEL_BREAKDOWN
    int cpuid;
    struct timespec k_start, k_end;
    cpuid = sched_getcpu();
#endif
    file_size = atomic_load(&fp->size);
    // printf("fname = %d, offset = %d, len = %d, fsize = %d\n", fp->fd, offset, len, file_size);
    // Make sure read size is greater than 0
    if (len == 0) {
        return 0;
    }

    // Invalid offsets
    if (offset >= file_size) {
        return 0;
    }


    // Reads to end of file
    // if (offset + len > file_size) {
    //     len = file_size - offset;
    // }


//     ///////////////////////
#ifdef NAP_USE_NAP_POLL
    cmd.fd = fd;
    cmd.rw = 0; // read
    cmd.queue_idx = fp->queue_idx;
    cmd.len = len;
    cmd.lba = slba;
    cmd.ofs = offset;
    cmd.vaddr = (unsigned long) buf;
    // printf("pread: fd = %d, rw = %d, cnt = %ld, offset = %ld, io_size = %ld, slba = %ld, ino = %d\n", fd, cmd.rw, cnt, offset, len, slba, fp->ino);
    ret = ioctl(userlib_info->nap_drv_fd, NAP_IOC_SUBMIT_IO, &cmd);
    if (ret != 0) {
        printf("Failed to submit IO\n");
        return -EINVAL; // todo: how to return error
    }
    if (offset + len > file_size) {
        total_bytes_read = file_size - offset;
    } else {
        total_bytes_read = len;
    }
#else
    cnt = len;
    while (cnt > 0) {
        // Since we are emulating, we use the actual LBA in the NVMe request
        // However, in the actual BypassD design, we would include the VBA
        // which the IOMMU would translate to LBA
        nap_ulib_log("pread: offset = %ld, cnt = %ld, file_size = %ld\n", offset, cnt, file_size);
        ret = file_get_lba(fp, cnt, offset, &slba, &io_size);
        if (ret == 1) {
            nap_ulib_log("pread err: offset = %ld, cnt = %ld, file_size = %ld\n", offset, cnt, file_size);
            return -EINVAL; // todo: how to return error
        }
        // printf("pread v2: offset = %ld, cnt = %ld, file_size = %ld, io_size = %ld\n", offset, cnt, file_size, io_size);
        /////// submit I/Os to NAP driver
        cmd.fd = fd;
        cmd.rw = 0; // read
        cmd.queue_idx = fp->queue_idx;
        cmd.len = io_size;
        cmd.lba = slba;
        cmd.ofs = offset;
        cmd.vaddr = (unsigned long) buf;

        // nap_ulib_log("pread: rw = %d, queue_idx = %d, len = %ld, lba = %ld, ofs = %ld, vaddr = %lx\n", cmd.rw, cmd.queue_idx, cmd.len, cmd.lba, cmd.ofs, cmd.vaddr);
        // printf("pread-submit: fd = %d, rw = %d, cnt = %ld, offset = %ld, io_size = %ld, slba = %ld\n", fd, cmd.rw, cnt, offset, io_size, slba);
#ifdef NAP_DEBUG_USER_KERNEL_BREAKDOWN
        clock_gettime(CLOCK_MONOTONIC, &k_start);
#endif
        ret = ioctl(userlib_info->nap_drv_fd, NAP_IOC_SUBMIT_IO, &cmd);
#ifdef NAP_DEBUG_USER_KERNEL_BREAKDOWN
        clock_gettime(CLOCK_MONOTONIC, &k_end);
#endif
        if (ret != 0) {
            printf("Failed to submit IO\n");
            return -EINVAL; // todo: how to return error
        }
        /////// submit I/Os to NAP driver

        bytes_read = (io_size < cnt) ? io_size : cnt;
        if (offset + bytes_read >= file_size) {
            bytes_read = file_size - offset;
            total_bytes_read += bytes_read;
            break;
        }
        // printf("pread-kk: rw = %d, cnt = %ld, offset = %ld, io_size = %ld, bytes_read = %ld, total_bytes_read = %ld\n", cmd.rw, cnt, offset, io_size, bytes_read, total_bytes_read);
        cnt -= bytes_read;
        offset += bytes_read;
        buf += bytes_read;
        total_bytes_read += bytes_read;
        
    }
#endif

#ifdef NAP_DEBUG_USER_KERNEL_BREAKDOWN
    nap_debug_kernel_ov[cpuid] += (k_end.tv_sec - k_start.tv_sec) * 1000000000 + (k_end.tv_nsec - k_start.tv_nsec);
    nap_debug_kernel_ov_cnt[cpuid]++;
#endif
    // printf("pread-ret: fd = %d, ret = %ld\n", fd, total_bytes_read);
    return total_bytes_read;
}

ssize_t nap_read(int fd, void *buf, size_t len)
{
    struct ulib_file *fp = &userlib_info->ulib_open_files[fd];
    size_t bytes_read = 0;
    loff_t offset = atomic_load(&fp->offset);
   
    bytes_read = nap_pread(fd, buf, len, offset);
    if(bytes_read > 0) {
        atomic_fetch_add(&fp->offset, bytes_read);
    }

    return bytes_read;
}

// TODO: Support for unaligned writes and writes smaller than 512B has not been fully integrated
// Below code doesn't support. It will be added soon.
ssize_t nap_pwrite(int fd, const void *buf, size_t len, off_t offset)
{
    size_t file_size;
    bool is_append = false;
    ssize_t ret;
    unsigned long slba = 0;
    loff_t cnt, io_size = 0;
    struct nap_rw_cmd cmd;
    struct ulib_file *fp = &userlib_info->ulib_open_files[fd];

    file_size = atomic_load(&fp->size);

    if (len == 0) {
        return 0;
    }

    if (fp->flags & O_APPEND) {
        is_append = true;
        offset = fp->append_offset;
    }

    // Parameter checks
    if (offset < 0) {
        nap_ulib_log("Offset < 0\n");
        return -EINVAL;
    }
    // printf("pwrite: fd = %d, rw = 1, cnt = %ld, offset = %ld, io_size = %ld, ino = %d\n", fd, cnt, offset, len, fp->ino);
    // TODO: Partial writes go through kernel
    if (offset % BLK_SIZE != 0 || len % BLK_SIZE != 0) {
        ret = posix_fops->PWRITE(fp->fd, buf, len, offset);  //syscall_no_intercept(SYS_pwrite64, fp->fd, buf, len, offset);
        posix_fops->FSYNC(fp->fd); // TODO:  if we use direct io? is fsync necassary? syscall_no_intercept(SYS_fsync, fp->fd); // Need to persist immediately
        fp->data_modified = false;
        fp->metadata_modified = false;
        return ret;
    }

    // Appends
    if ((offset + len) > file_size) {
        // TODO: need to handle writes < PAGE_SIZE
        // for this scenario, we should use fallocate to allocate blocks then access them in the user space ... like BypassD
        // printf("[nap-ulib append] offset = %llu, len = %llu\n", offset, len);
        ret = posix_fops->PWRITE(fp->fd, buf, len, offset); // syscall_no_intercept(SYS_pwrite64, fp->fd, buf, len, offset);
        posix_fops->FSYNC(fp->fd); // syscall_no_intercept(SYS_fsync, fp->fd);
        fp->data_modified = false;
        fp->metadata_modified = false;

        if ((ret > 0) && ((offset + ret) > fp->size)) {
            atomic_store(&fp->size, offset + ret); // Increase size of file
        }
        return ret;
    }

    // Overwrites and all I/Os are block aligned ...
    // printf("[nap-ulib overwite] offset = %llu, len = %llu\n", offset, len);
#ifdef NAP_USE_NAP_POLL
    cmd.fd = fd;
    cmd.rw = 1; // read
    cmd.queue_idx = fp->queue_idx;
    cmd.len = len;
    cmd.lba = slba;
    cmd.ofs = offset;
    cmd.vaddr = (unsigned long) buf;
    ret = ioctl(userlib_info->nap_drv_fd, NAP_IOC_SUBMIT_IO, &cmd);
    if (ret != 0) {
        printf("Failed to submit IO\n");
        return -EINVAL; // todo: how to return error
    }
#else
    cnt = len;
    while (cnt > 0) {
        ret = file_get_lba(fp, cnt, offset, &slba, &io_size);
        if (ret != 0) {
            nap_ulib_log("Failed to get LBA\n");
            return -EINVAL;
        }

        // bytes_written is required here
        // how to handle partial writes with nap?
        
        /////// submit I/Os to NAP driver
        cmd.fd = fd;
        cmd.rw = 1; // write
        cmd.queue_idx = fp->queue_idx;
        cmd.len = io_size;
        cmd.lba = slba;
        cmd.ofs = offset;
        cmd.vaddr = (unsigned long) buf;
        ret = ioctl(userlib_info->nap_drv_fd, NAP_IOC_SUBMIT_IO, &cmd);
        if (ret != 0) {
            nap_ulib_log("Failed to submit IO\n");
            return -EINVAL; // todo: how to return error
        }
        /////// submit I/Os to NAP driver

        cnt -= io_size;
        offset += io_size;
        buf += io_size;
    }
#endif
    if (is_append) {
        fp->append_offset += len;
    }
    nap_ulib_log("Normal, len = %d\n", len);
    return len;
}

ssize_t nap_write(int fd, const void *buf, size_t len)
{
    ssize_t bytes_written = 0;
    struct ulib_file *fp = &userlib_info->ulib_open_files[fd];
    off_t offset = atomic_load(&fp->offset);
   
    bytes_written = nap_pwrite(fd, buf, len, offset);
    if(bytes_written > 0) {
        atomic_fetch_add(&fp->offset, bytes_written);
    }

    return bytes_written;
}

off_t nap_lseek(int fd, off_t offset, int whence)
{
    off_t result;
    struct ulib_file *fp = &userlib_info->ulib_open_files[fd];
    switch (whence) {
        case SEEK_END:
            fp->offset = fp->size + offset;
            break;
        case SEEK_CUR:
            fp->offset += offset;
            break;
        case SEEK_SET:
            fp->offset = offset;
            break;
        default:
            result = -EINVAL;
            break;
    }

    if (result == -EINVAL)
        return result;
    
    return fp->offset;
}

int nap_fallocate(int fd, int mode, off_t offset, off_t len)
{
    int ret;
    struct ulib_file *fp = &userlib_info->ulib_open_files[fd];

    ret = posix_fops->FALLOCATE(fp->fd, mode, offset, len); // syscall_no_intercept(SYS_fallocate, fp->fd, mode, offset, len);
    if (ret != 0)
        return ret;

    switch (mode) {
        case 0:
        case FALLOC_FL_KEEP_SIZE:
            atomic_store(&fp->size, offset + len);
            fp->append_offset = fp->size;
            break;
        case FALLOC_FL_COLLAPSE_RANGE:
            atomic_fetch_sub(&fp->size, len); // TODO: need to verify this
            fp->append_offset = fp->size;
            break;
        default:
            break;
    }

    fp->metadata_modified = true;

    return ret;
}

int nap_ftruncate(int fd, off_t length)
{
    int ret;
    struct ulib_file *fp = &userlib_info->ulib_open_files[fd];

    ret = posix_fops->FTRUNCATE(fp->fd, length); //syscall_no_intercept(SYS_ftruncate, fp->fd, length);
    if (ret != 0)
        return ret;

    atomic_store(&fp->size, length);
    fp->metadata_modified = true;
    return ret;
}

void nap_fdatasync(int fd)
{
    struct ulib_file *fp = &userlib_info->ulib_open_files[fd];
    // we do not need to do anything here
    // as for every write, they are direct I/Os
    // so we don't need to flush data here
    if (fp->data_modified) {
        nap_fdatasync(fd);
        fp->data_modified = false;
    }
}

void nap_fsync(int fd)
{
    struct ulib_file *fp = &userlib_info->ulib_open_files[fd];
    if (fp->metadata_modified) {
        // syscall_no_intercept(SYS_fsync, fd);
        posix_fops->FSYNC(fp->fd);
        fp->metadata_modified = false;
    }
    nap_fdatasync(fd);
}

int ulib_file_is_open(int fd)
{
    struct ulib_file *fp = &userlib_info->ulib_open_files[fd];
    return fp->opened;
}

void nap_ulib_exit()
{
    int initialized = 0;

    if (__atomic_compare_exchange_n(&ulib_initialized, &initialized, 0, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        nap_ulib_log("[%s]: Already exited\n", __func__);
        return;
    }
    
    if(userlib_info && userlib_info->nap_drv_fd > 0) {
        posix_fops->CLOSE(userlib_info->nap_drv_fd);
        // syscall_no_intercept(SYS_close, userlib_info->nap_drv_fd);
    }
#ifdef NAP_DEBUG_USER_KERNEL_BREAKDOWN
    unsigned long total_kernel_ov = 0;
    unsigned long total_kernel_ov_cnt = 0;
    unsigned long total_kernel_ov_avg = 0;
    for (int i = 0; i < 50; i++) {
        if (nap_debug_kernel_ov_cnt[i] > 0) {
            total_kernel_ov += nap_debug_kernel_ov[i];
            total_kernel_ov_cnt += nap_debug_kernel_ov_cnt[i];
        }
    }
    printf("Total kernel overhead: %lu ns, Avg: %lu ns\n", total_kernel_ov, total_kernel_ov_cnt > 0 ? (total_kernel_ov / total_kernel_ov_cnt) : 0);
#endif
#ifdef NAP_DEBUG_FMAP_OVERHEAD
    unsigned long avg_fmap_latency = nap_debug_fmap_latency / nap_debug_fmap_latency_cnt;
    printf("Total fmap latency: %lu ns, Avg: %lu ns\n", nap_debug_fmap_latency, nap_debug_fmap_latency_cnt > 0 ? avg_fmap_latency : 0);
#endif
    nap_ulib_log("Exiting..\n");
}

int nap_ulib_init(const char *dev_path)
{
    int initialized = 0;

    nap_ulib_log("userlib init ... \n");
    if (!__atomic_compare_exchange_n(&ulib_initialized, &initialized, 1, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        nap_ulib_log("Already initialized\n");
        return 0;
    }

    userlib_info = (struct ulib_info *) malloc(sizeof(struct ulib_info));
    memset(userlib_info, 0, sizeof(struct ulib_info));

    char dev_path_str[128] = {0};
    sprintf(dev_path_str, "/proc/nap/%s/ioctl", dev_path);
    nap_ulib_log("NAP device path: %s\n", dev_path_str);
    userlib_info->nap_drv_fd = posix_fops->OPEN(dev_path_str, O_RDWR);
    if (userlib_info->nap_drv_fd < 0) {
        nap_ulib_log("Fail to connect to NAP module \n");
        return -1;
    }
    nap_ulib_log("Connected to NAP module, fd = %d\n", userlib_info->nap_drv_fd);
    return 0;
}

