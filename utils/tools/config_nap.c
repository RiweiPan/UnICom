
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/ioctl.h>


#define NAP_IOC_MAGIC  0x46
#define NAP_IOC_DEBUG_READ _IOW(NAP_IOC_MAGIC, 1, struct nap_rw_cmd)
#define NAP_IOC_ENABLE _IOW(NAP_IOC_MAGIC, 2, long)
#define NAP_IOC_DISABLE _IOW(NAP_IOC_MAGIC, 3, long)
#define NAP_IOC_SUBMIT_IO _IOW(NAP_IOC_MAGIC, 4, struct nap_rw_cmd)
#define NAP_IOC_REGISTER_FILE _IOW(NAP_IOC_MAGIC, 5, struct nap_reg)
#define NAP_IOC_UNREGISTER_FILE _IOW(NAP_IOC_MAGIC, 6, struct nap_reg)


int main(int argc, char *argv[])
{
    int fd;
    int ret;
    int enable;
    int nr_queues = 1;
    char *dev_name, *dev_base_name;
    char ctrl_path[128] = {0};

    if (argc < 3) {
        printf("Usage: %s <dev_name> <enable> <nr_queues>\n", argv[0]);
        return -1;
    }

    dev_name = argv[1];
    dev_base_name = basename(dev_name);

    enable = atoi(argv[2]);
    if(argv[3] != NULL) {
        nr_queues = atoi(argv[3]);
    }
    
    sprintf(ctrl_path, "/proc/nap/%s/ioctl", dev_base_name);
    printf("NAP control path: %s\n", ctrl_path);
    fd = open(ctrl_path, O_RDWR);
    if (fd <= 0) {
        printf("Fail to open to NAP module \n");
        return -1;
    }

    if (enable) {
        ret = ioctl(fd, NAP_IOC_ENABLE, &nr_queues);
    } else {
        ret = ioctl(fd, NAP_IOC_DISABLE, &nr_queues);
    }

    if (ret != 0) {
        printf("Fail to enable/disable NAP module \n");
        return -1;
    }

    close(fd);
    return 0;
}