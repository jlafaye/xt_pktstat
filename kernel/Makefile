obj-m := xt_pktstat.o
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

