cd /home/ubuntu
mkdir -p hw3 

docker container ls

docker  exec -it 0315  /bin/bash

insmod kfetch_mod_314540035.ko
rmmod kfetch_mod_314540035 
make
dmesg
 
 /dev/kfetch 
 kfetch
 cat /dev/kfetch

 cd /home/ubuntu/initramfs/
find . | cpio -o -H newc | gzip > ../initramfs.cpio.gz
cd ..

qemu-system-riscv64 -nographic -machine virt -m 1024 -smp 4 \
    -kernel hw3/Image \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 loglevel=3 hostname=my-riscv-vm"
