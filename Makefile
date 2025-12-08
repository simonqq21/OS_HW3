obj-m += kfetch_mod_314540035.o 

# You should adjust based on your own directory structure
PWD := $(CURDIR) 
KDIR ?= "$(PWD)/linux-v6.8-devkit"
ARCH := x86
SKIP_BTF_GEN=1

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

# 	@echo $(MAKE)
# 	@echo kdir = $(KDIR)
# 	@echo $(ARCH)
# 	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules

clean: 
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 