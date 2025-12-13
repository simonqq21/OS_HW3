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