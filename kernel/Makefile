obj-m := xt_pktstat.o
xt_pktstat-objs := pktstat.o
#obj-y := 
ifeq ($(DISTRO),RHEL5)
xt_pktstat-objs += kfifo.o compat.o
EXTRA_CFLAGS += -DRHEL5
endif
MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS += -I$(PWD)/include

all:
	$(MAKE) -C $(KERNEL_DIR) M=$$PWD;

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$$PWD $@;

modules_install:
	$(MAKE) -C $(KERNEL_DIR) M=$$PWD $@;

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$$PWD $@;

