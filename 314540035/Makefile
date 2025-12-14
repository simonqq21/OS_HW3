obj-m += kfetch_mod_314540035.o

# You should adjust based on your own directory structure
PWD := $(CURDIR) 
KDIR ?= ../linux-v6.8-devkit
ARCH ?= riscv
CROSS_COMPILE ?= riscv64-linux-gnu-

all:	
	@echo $(ARCH)
	@echo kdir = $(KDIR)
	@echo $(CROSS_COMPILE)
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules
	
all-x86:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean: 
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 

load: 
	sudo insmod kfetch_mod_314540035.ko 

unload: 
	-sudo rmmod -f kfetch_mod_314540035 

reload: unload load 

read: 
	@cat /dev/kfetch 

write: 
	@echo 7 > /dev/kfetch