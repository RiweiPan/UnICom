#ifndef _USERLIB_H
#define _USERLIB_H

#include <stdbool.h>

// #define NAP_DEBUG_USER_KERNEL_BREAKDOWN
// #define NAP_ULIB_DEBUG
// #define NAP_BANDWIDTH_STAT
// #define NAP_DEBUG_CHECK_FMAP
// #define NAP_DEBUG_FMAP_OVERHEAD

// #define NAP_USE_NAP_POLL

#ifdef NAP_ULIB_DEBUG
#define nap_ulib_log(fmt, ...) \
	do{printf("[ULIB-DBG]:(%s):%d: " fmt, __func__, __LINE__, ##__VA_ARGS__);} while(0)
#else
#define nap_ulib_log(fmt, ...) \
	do{} while(0)
#endif

#define MAX_FILES 1024

#define BLK_SIZE 512
#define LB_SIZE  4096
#define BLK_ALIGN(len)      (((len)+((BLK_SIZE)-1))&(~((typeof(len))(BLK_SIZE)-1)))
#define BLK_DOWN_ALIGN(len) ((len)&(~((typeof(len))(BLK_SIZE)-1)))

#define PAGE_SHIFT		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))
#define _ALIGN(len, size)   (typeof(len))(((len)+((size)-1))&(~((typeof(len))(size)-1)))
#define PAGE_ALIGN(len) _ALIGN(len, PAGE_SIZE)

#define __PHYSICAL_MASK_SHIFT	52
#define __PHYSICAL_MASK		((unsigned long long)((1ULL << __PHYSICAL_MASK_SHIFT) - 1))
#define PHYSICAL_PAGE_MASK 	(((signed long)PAGE_MASK) & __PHYSICAL_MASK)
#define PTE_PFN_MASK		((unsigned long)PHYSICAL_PAGE_MASK)

#define NAP_IOC_MAGIC  0x46
#define NAP_IOC_DEBUG_READ _IOW(NAP_IOC_MAGIC, 1, struct nap_rw_cmd)
#define NAP_IOC_ENABLE _IOW(NAP_IOC_MAGIC, 2, long)
#define NAP_IOC_DISABLE _IOW(NAP_IOC_MAGIC, 3, long)
#define NAP_IOC_SUBMIT_IO _IOW(NAP_IOC_MAGIC, 4, struct nap_rw_cmd)
#define NAP_IOC_REGISTER_FILE _IOW(NAP_IOC_MAGIC, 5, struct nap_reg)
#define NAP_IOC_UNREGISTER_FILE _IOW(NAP_IOC_MAGIC, 6, struct nap_reg)

struct file_ops {
    char *name;
    int (*OPEN)(const char *path, int oflag, ...);
    int (*OPENAT)(int dfd, const char *path, int oflag, ...);
    int (*OPEN64)(const char *path, int oflag, ...);
    int (*OPENAT64)(int dfd, const char *path, int oflag, ...);
    int (*CREATE)(const char *path, mode_t mode);
    int (*CLOSE)(int fd);
    ssize_t (*READ)(int fd, void *buf, size_t nbytes);
    ssize_t (*WRITE)(int fd, const void *buf, size_t nbytes);
    ssize_t (*PREAD)(int fd, void *buf, size_t count, off_t offset);
    ssize_t (*PWRITE)(int fd, const void *buf, size_t count, off_t offset);
    off_t (*LSEEK)(int fd, off_t offset, int whence);
    int (*FALLOCATE)(int fd, int mode, off_t offset, off_t len);
    int (*FTRUNCATE)(int fd, off_t length);
    int (*FDATASYNC)(int fd);
    int (*FSYNC)(int fd);
};

struct ulib_file {
    int fd;
    size_t size;
    loff_t offset;
    int    flags;
    mode_t mode;
    loff_t append_offset;

    unsigned long old_fva;
    unsigned long fva;

    int opened;
    int ino;
    bool data_modified;
    bool metadata_modified;
    int queue_idx;
};

struct ulib_info {
    struct ulib_file ulib_open_files[MAX_FILES];
    int nr_open_files;
    int nap_drv_fd;
};

struct nap_reg {
    int queue_idx;
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

int ulib_file_is_open(int fd);

// hooks
int nap_open(const char* filename, int flags, mode_t mode);
int nap_close(int fd);
ssize_t nap_pread(int fd, void *buf, size_t len, off_t offset);
ssize_t nap_read(int fd, void *buf, size_t len);
ssize_t nap_pwrite(int fd, const void *buf, size_t count, off_t offset);
ssize_t nap_write(int fd, const void *buf, size_t len);
off_t nap_lseek(int fd, off_t offset, int whence);
int nap_fallocate(int fd, int mode, off_t offset, off_t len);
int nap_ftruncate(int fd, off_t length);
void nap_fdatasync(int fd);
void nap_fsync(int fd);

int nap_ulib_init(const char *dev_path);
void nap_ulib_exit();
#endif