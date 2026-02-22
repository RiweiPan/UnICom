CURRENT_PATH := $(shell pwd)
QEMU_KERNEL_PATH1 := /home/hubery/myworks/nap/test/qemu-test/linux-6.5.1-qemu
QEMU_KERNEL_PATH2 := /home/hubery/myworks/nap/test/qemu-test/linux-5.4-qemu
IOCP_MODE ?= $(NAP_POLL)

obj-m := nap.o
nap-y := nap_main.o nap_dma.o nap_nvme.o nap_nvme_queues.o nap_nvme_request.o
ccflags-y := -O2

# 处理IOCP_MODE
ifeq ($(IOCP_MODE),1)
ccflags-y += -DNAP_USE_NAP_POLL
$(info Using nap_poll, IOCP_MODE: $(IOCP_MODE))
else
$(info Using pure_poll, IOCP_MODE: $(IOCP_MODE))
endif

# 通用编译函数
define build_module
	$(MAKE) -C $1 M=$(CURRENT_PATH) EXTRA_CFLAGS="$(ccflags-y)$2" modules
endef

# QEMU目标版本检测
QEMU6_MAJOR_VER := $(shell basename $(QEMU_KERNEL_PATH1) | sed 's/linux-\([0-9]\+\)\..*/\1/')
QEMU5_MAJOR_VER := $(shell basename $(QEMU_KERNEL_PATH2) | sed 's/linux-\([0-9]\+\)\..*/\1/')

# 编译目标规则
qemu6:
	$(call build_module,$(QEMU_KERNEL_PATH1),$(if $(filter 6,$(QEMU6_MAJOR_VER)), -DNAP_KERNEL_VER_6))

qemu5:
	$(call build_module,$(QEMU_KERNEL_PATH2),$(if $(filter 5,$(QEMU5_MAJOR_VER)),))

host:
	$(eval HOST_KERNEL_VER := $(shell uname -r))
	$(eval HOST_MAJOR_VER := $(shell echo $(HOST_KERNEL_VER) | cut -d. -f1))
	$(call build_module,/lib/modules/$(HOST_KERNEL_VER)/build,$(if $(filter 6,$(HOST_MAJOR_VER)), -DNAP_KERNEL_VER_6))

host_poll: host

# 清理规则
clean:
	$(MAKE) -C $(QEMU_KERNEL_PATH1) M=$(CURRENT_PATH) clean
	$(MAKE) -C $(QEMU_KERNEL_PATH2) M=$(CURRENT_PATH) clean
	$(eval HOST_KERNEL_VER := $(shell uname -r))
	$(MAKE) -C /lib/modules/$(HOST_KERNEL_VER)/build M=$(CURRENT_PATH) clean

.PHONY: qemu6 qemu5 host host_poll clean