#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <stdarg.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>
#include "ulib.h"

#ifdef NAP_BANDWIDTH_STAT
struct io_bytes {
    unsigned long long read_bytes;
    unsigned long long write_bytes;
} __attribute__((aligned(64)));

static struct timespec start_time;
static struct timespec end_time;
static struct io_bytes io_bytes_per_cpu[50];
#endif

#define LIBC_SO_LOC "/lib/x86_64-linux-gnu/libc.so.6"
void initialize(void) __attribute__((constructor));
void finalize(void) __attribute__((destructor));

// open & close
int open(const char *path, int oflag, ...) __attribute__ ((weak, alias("shim_do_open")));
int shim_do_open(const char *path, int oflag, ...);
int openat(int dfd, const char *path, int oflag, ...) __attribute__ ((weak, alias("shim_do_openat")));
int open64(const char *path, int oflag, ...) __attribute__ ((weak, alias("shim_do_open")));
int creat(const char *path, mode_t mode) __attribute__ ((weak, alias("shim_do_creat")));
int openat64(int dfd, const char *path, int oflag, ...) __attribute__ ((weak, alias("shim_do_openat")));
int shim_do_openat(int dfd, const char *path, int oflag, ...);
int close(int fd) __attribute__ ((weak, alias("shim_do_close")));
int shim_do_close(int fd);

// read & write
ssize_t read(int fd, void *buf, size_t nbytes) __attribute__ ((weak, alias("shim_do_read")));
ssize_t shim_do_read(int fd, void *buf, size_t nbytes);
ssize_t write(int fd, const void *buf, size_t nbytes) __attribute__ ((weak, alias("shim_do_write")));
ssize_t shim_do_write(int fd, const void *buf, size_t nbytes);


// pread & pwrite
ssize_t pread(int fd, void *buf, size_t count, off_t offset) __attribute__ ((weak, alias("shim_do_pread64")));
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) __attribute__ ((weak, alias("shim_do_pwrite64")));

ssize_t pread64(int fd, void *buf, size_t count, off_t offset) __attribute__ ((weak, alias("shim_do_pread64")));
ssize_t shim_do_pread64(int fd, void *buf, size_t count, off_t offset);
ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) __attribute__ ((weak, alias("shim_do_pwrite64")));
ssize_t shim_do_pwrite64(int fd, void *buf, size_t count, off_t offset);

// others
off_t lseek(int fd, off_t offset, int whence) __attribute__ ((weak, alias("shim_do_lseek")));
off_t shim_do_lseek(int fd, off_t offset, int whence);

// others
int fallocate(int fd, int mode, off_t offset, off_t len) __attribute__ ((weak, alias("shim_do_fallocate")));
int shim_do_fallocate(int fd, int mode, off_t offset, off_t len);
int ftruncate(int fd, off_t length) __attribute__ ((weak, alias("shim_do_ftruncate")));
int shim_do_ftruncate(int fd, off_t length);
int fdatasync(int fd) __attribute__ ((weak, alias("shim_do_fdatasync")));
int shim_do_fdatasync(int fd);
int fsync(int fd) __attribute__ ((weak, alias("shim_do_fsync")));
int shim_do_fsync(int fd);

 // Max length of the full file path
#define MAX_PATH_LEN 4096
const char DEVICE_DIR[32] = "/mnt/nvme";
struct file_ops *posix_fops;

static inline void *dlsym_safe(void *so_p, const char *func_name)
{
    void *dlsym_result = dlsym(so_p, func_name);
    if(!dlsym_result) {
        nap_ulib_log("dlsym error, func: %s\n", func_name);
        _exit(-1);
    }
    return dlsym_result;
}

static int init_posix_interfaces(void)
{
    void *libc_addr = NULL, *dlsym_addr;

    libc_addr = dlopen(LIBC_SO_LOC, RTLD_LAZY|RTLD_LOCAL);
    if(!libc_addr) {
        nap_ulib_log("Open Libc Error!\n");
        return -1;
    }

    posix_fops = (struct file_ops *) malloc(sizeof(struct file_ops));
    if(!posix_fops) {
        nap_ulib_log("Alloc posix_fops Error!\n");
        return -1;
    }

    posix_fops->name = "posix";
    dlsym_addr = dlsym_safe(libc_addr, "open");
    posix_fops->OPEN = (int (*)(const char *path, int oflag, ...)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "openat");
    posix_fops->OPENAT = (int (*)(int dfd, const char *path, int oflag, ...)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "open64");
    posix_fops->OPEN64 = (int (*)(const char *path, int oflag, ...)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "openat64");
    posix_fops->OPENAT64 = (int (*)(int dfd, const char *path, int oflag, ...)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "creat");
    posix_fops->CREATE = (int (*)(const char *path, mode_t mode)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "close");
    posix_fops->CLOSE = (int (*)(int fd)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "read");
    posix_fops->READ = (ssize_t (*)(int fd, void *buf, size_t length)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "write");
    posix_fops->WRITE = (ssize_t (*)(int fd, const void *buf, size_t length)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "lseek");
    posix_fops->LSEEK = (__off_t (*)(int fd, __off_t offset, int whence)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "pread64");
    posix_fops->PREAD = (ssize_t (*)(int fd, void *buf, size_t count, off_t offset)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "pwrite64");
    posix_fops->PWRITE = (ssize_t (*)(int fd, const void *buf, size_t count, off_t offset)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "fallocate");
    posix_fops->FALLOCATE = (int (*)(int fd, int mode, off_t offset, off_t len)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "ftruncate");
    posix_fops->FTRUNCATE = (int (*)(int fd, off_t length)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "fdatasync");
    posix_fops->FDATASYNC = (int (*)(int fd)) dlsym_addr;
    dlsym_addr = dlsym_safe(libc_addr, "fsync");
    posix_fops->FSYNC = (int (*)(int fd)) dlsym_addr;
    
    return 0;
}


/////////////// hook functions ///////////////
/**
 * Note: the three arugments of shim_do_open only can hook the open function with three arguments.
 *           cannot hook the open function with two arguments.
 */
int shim_do_open(const char *filename, int flags, ...)
{
    char fullpath[MAX_PATH_LEN];
    int fd = 0;
    mode_t mode;
    va_list arg;

    if(filename == NULL) {
        return -EINVAL;
    }
    nap_ulib_log("shim open filename = %s, flags = %d\n", filename, (flags & O_DIRECT));
    memset(fullpath, 0, sizeof(fullpath));

    if (filename[0] == '/') {
        strcpy(fullpath, filename);
    } else {
        if(getcwd(fullpath, sizeof(fullpath)) == NULL)  {
            return -EINVAL;
        }
        if(strlen(filename) >= 2 && (filename[0] == '.' && filename[1] == '/')) {
            strcat(fullpath, "/");
            strcat(fullpath, filename + 2);
        } else {
            strcat(fullpath, "/");
            strcat(fullpath, filename);
        }
    }

    if(flags & O_CREAT) {
        va_start(arg, flags);
        mode = va_arg(arg, int);
        va_end(arg);
        //printf("full path = %s, is_direct = %d\n", fullpath, flags & O_DIRECT);
        if (strstr(fullpath, DEVICE_DIR) != NULL && (flags & O_DIRECT)) {
            fd = nap_open(fullpath, flags, mode);
            nap_ulib_log("filename=%s fd = %d\n", fullpath, fd);
            if(fd <= 0) {
                perror("do open");
            }
        } else {
            fd = posix_fops->OPEN(filename, flags, mode);
        } 
    } else {
        if (strstr(fullpath, DEVICE_DIR) != NULL && (flags & O_DIRECT)) {
            fd = nap_open(fullpath, flags, 0666);
            nap_ulib_log("nap open filename=%s fd = %d\n", fullpath, fd);
        } else {
            fd = posix_fops->OPEN(filename, flags);
            nap_ulib_log("normal open filename=%s fd = %d\n", fullpath, fd);
        }
    }

    return fd;
}

int shim_do_openat(int dfd, const char *filename, int flags, ...)
{
    char fullpath[MAX_PATH_LEN];
    int fd = 0;
    mode_t mode;
    va_list arg;

    if(filename == NULL) {
        return -EINVAL;
    }
    nap_ulib_log("filename = %s\n", filename);
    memset(fullpath, 0, sizeof(fullpath));
    nap_ulib_log("dfd = %d filename = %s flags = 0x%x\n", dfd, filename, flags);
    if (filename[0] == '/') {
        strcpy(fullpath, filename);
    } else if (dfd == AT_FDCWD) {
        if (getcwd(fullpath, sizeof(fullpath)) == NULL) {
            return -EINVAL;
        }
        
        if(strlen(filename) >= 2 && (filename[0] == '.' && filename[1] == '/')) {
            strcat(fullpath, "/");
            strcat(fullpath, filename + 2);
        } else {
            strcat(fullpath, "/");
            strcat(fullpath, filename);
        }
    } else {
        // TODO: Need to handle relative openat
        nap_ulib_log(" Don't know how to handle relative openat\n");
        fd = posix_fops->OPENAT(dfd, filename, flags);
        return fd;
    }

    if(flags & O_CREAT) {
        va_start(arg, flags);
        mode = va_arg(arg, int);
        va_end(arg);
        if (strstr(fullpath, DEVICE_DIR) != NULL && (flags & O_DIRECT)) {
            fd = nap_open(fullpath, flags, mode);
            nap_ulib_log("filename=%s fd = %d\n", fullpath, fd);
        } else {
            fd = posix_fops->OPENAT(dfd, filename, flags, mode);
        } 
    } else {
        if (strstr(fullpath, DEVICE_DIR) != NULL && (flags & O_DIRECT)) {
            fd = nap_open(fullpath, flags, 0666);
            nap_ulib_log("filename=%s fd = %d\n", fullpath, fd);
        } else {
            fd = posix_fops->OPENAT(dfd, filename, flags);
        }
    }

    return fd;
}

int shim_do_creat(const char *filename, mode_t mode)
{
    int fd = 0;
    fd = shim_do_open(filename, O_CREAT | O_WRONLY | O_TRUNC, mode);
    return fd;
}

int shim_do_close(int fd)
{
    if (ulib_file_is_open(fd)) {
        nap_close(fd);
        return 0;
    } else { // Not opened with BypassD interface
        return posix_fops->CLOSE(fd);
    }
}

ssize_t shim_do_read(int fd, void *buf, size_t count)
{
    ssize_t read_size = 0;

    if (ulib_file_is_open(fd)) {
        read_size = nap_read(fd, buf, count);
    } else { // Not opened with BypassD interface
        read_size = posix_fops->READ(fd, buf, count);
    }

    nap_ulib_log("fd = %d size = %ld\n", fd, count);
#ifdef NAP_BANDWIDTH_STAT
    int cpuid = sched_getcpu();
    io_bytes_per_cpu[cpuid].read_bytes += read_size;
    //printf("[shim_do_read] cpu = %d, read_bytes = %lu\n", cpuid, io_bytes_per_cpu[cpuid].read_bytes);
#endif
    return read_size;
}

ssize_t shim_do_pread64(int fd, void *buf, size_t count, off_t offset)
{
    ssize_t read_size = 0;
    
    if (ulib_file_is_open(fd)) {
        nap_ulib_log("p1 fd = %d, offset=%lu, count=%lu\n", fd, offset, count);
        read_size = nap_pread(fd, buf, count, offset);
    } else {
        nap_ulib_log("p2 fd = %d, offset=%lu, count=%lu\n", fd, offset, count);
        read_size = posix_fops->PREAD(fd, buf, count, offset);
    }
#ifdef NAP_BANDWIDTH_STAT
    int cpuid = sched_getcpu();
    io_bytes_per_cpu[cpuid].read_bytes += read_size;
    //printf("[shim_do_pread64] cpu = %d, read_size = %lu\n", cpuid, read_size);
#endif
    return read_size;
}

ssize_t shim_do_pwrite64(int fd, void *buf, size_t count, off_t offset)
{
    ssize_t write_size = 0;
    if (ulib_file_is_open(fd)) {
        write_size = nap_pwrite(fd, buf, count, offset);
    } else {
        // {
        //     struct stat st;
        //     fstat(fd, &st);
        //     printf("pwrite-normal: fd = %d, rw = 1, offset = %ld, io_size = %ld, ino = %d\n", fd, offset, count, st.st_ino);
        // }
        write_size = posix_fops->PWRITE(fd, buf, count, offset);
    }
#ifdef NAP_BANDWIDTH_STAT
    int cpuid = sched_getcpu();
    io_bytes_per_cpu[cpuid].write_bytes += write_size;
#endif
    return write_size;
}

ssize_t shim_do_write(int fd, const void *buf, size_t count)
{
    ssize_t write_size = 0;
    if (ulib_file_is_open(fd)) {
        write_size = nap_write(fd, buf, count);
    } else {
        //         {
        //     struct stat st;
        //     fstat(fd, &st);
        //     printf("write-normal: fd = %d, rw = 1, io_size = %ld, ino = %d, size = %d\n", fd, count, st.st_ino, st.st_size);
        // }
        write_size = posix_fops->WRITE(fd, buf, count);
    }
#ifdef NAP_BANDWIDTH_STAT
    int cpuid = sched_getcpu();
    io_bytes_per_cpu[cpuid].write_bytes += write_size;
#endif
    return write_size;
}

off_t shim_do_lseek(int fd, off_t offset, int whence)
{
    off_t ret;
    if (ulib_file_is_open(fd)) {
        ret = nap_lseek(fd, offset, whence);
    } else {
        ret = posix_fops->LSEEK(fd, offset, whence);
    }
    return ret;
}

int shim_do_fallocate(int fd, int mode, off_t offset, off_t len)
{
    int ret;
    if (ulib_file_is_open(fd)) {
        ret = nap_fallocate(fd, mode, offset, len);
    } else {
        ret = posix_fops->FALLOCATE(fd, mode, offset, len);
    }
    return ret;
}

int shim_do_ftruncate(int fd, off_t length)
{
    int ret;
    if (ulib_file_is_open(fd)) {
        ret = nap_ftruncate(fd, length);
    } else {
        ret = posix_fops->FTRUNCATE(fd, length);
    }
    return ret;
}

int shim_do_fdatasync(int fd)
{
    int ret = 0;
    if (ulib_file_is_open(fd)) {
        nap_fdatasync(fd);
    } else {
        ret = posix_fops->FDATASYNC(fd);
    }

    return ret;
}

int shim_do_fsync(int fd)
{
    int ret = 0;
    if (ulib_file_is_open(fd)) {
        nap_fsync(fd);
    } else {
        ret = posix_fops->FSYNC(fd);
    }

    return ret;
}

void initialize(void)
{
    int ret;
    init_posix_interfaces();

    char *mntpath = getenv("NAP_MNTPATH");
    if(mntpath != NULL && strlen(mntpath) > 0) {
        memset(DEVICE_DIR, 0, sizeof(DEVICE_DIR));
        strcpy(DEVICE_DIR, mntpath);
    }

    char *dev_path = getenv("NAP_DEVPATH");
    if(dev_path != NULL && strlen(dev_path) > 0) {
        printf("NAP_DEVPATH is set to %s\n", dev_path);
        ret = nap_ulib_init(dev_path);
        
    } else {
        printf("NAP_DEVPATH is not set, use default nvme0n1\n");
        ret = nap_ulib_init("nvme0n1");
    }

    nap_ulib_log("Target directory: %s\n", DEVICE_DIR);
    if (ret != 0) {
        nap_ulib_log("Error initializating library\n");
        return;
    }
#ifdef NAP_BANDWIDTH_STAT
    clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif
}

void finalize(void)
{
#ifdef NAP_BANDWIDTH_STAT
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    unsigned long long read_bytes = 0;
    unsigned long long write_bytes = 0;
    unsigned long long total_bytes = 0;
    unsigned long long total_time = 0;
    double total_time_in_s = 0;

    for (int i = 0; i < 50; i++) {
        unsigned long long cpu_write_bytes = io_bytes_per_cpu[i].write_bytes;
        unsigned long long cpu_read_bytes = io_bytes_per_cpu[i].read_bytes;
        if(cpu_write_bytes + cpu_read_bytes > 0) {
            write_bytes += cpu_write_bytes;
            read_bytes += cpu_read_bytes;
            total_bytes += cpu_write_bytes + cpu_read_bytes;
            printf("cpu = %d, total_bytes = %lu\n", i, cpu_write_bytes + cpu_read_bytes);
        }
    }
    total_time = (end_time.tv_sec - start_time.tv_sec) * 1000000000 + (end_time.tv_nsec - start_time.tv_nsec);
    total_time_in_s = (double)total_time / 1000000000;
    /**
     * Note that the bandwidth is only a rough estimivation, as after loading the ulib, the user threads may wait for a long time before 
     * performing I/Os.
     */
    printf("Total bandwidth: %f MB/s, runtime = %f s \n", (double) total_bytes / 1024.0 / 1024.0 / total_time_in_s, total_time_in_s);
#endif
    nap_ulib_log("Exiting library\n");
    nap_ulib_exit();
}

