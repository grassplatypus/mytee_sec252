# MyTEE TOCTOU Attack Modules Makefile

obj-m += toctou_attacker.o
obj-m += toctou_victim.o

KDIR ?= /home/grassplatypus/mytee_sec252/linux
PWD := $(shell pwd)

# Cross-compile for ARM
CROSS_COMPILE ?= arm-linux-gnueabihf-
ARCH ?= arm

all:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) clean

# Install to a specific directory for deployment
INSTALL_DIR ?= $(PWD)/deploy
install: all
	mkdir -p $(INSTALL_DIR)
	cp *.ko $(INSTALL_DIR)/
	cp run_attack.sh $(INSTALL_DIR)/
	chmod +x $(INSTALL_DIR)/run_attack.sh

.PHONY: all clean install
