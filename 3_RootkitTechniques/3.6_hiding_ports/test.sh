sudo dmesg -C && 

make clean &&
make &&
clear &&

sudo insmod rootkit.ko &&

sudo rmmod rootkit &&

dmesg
