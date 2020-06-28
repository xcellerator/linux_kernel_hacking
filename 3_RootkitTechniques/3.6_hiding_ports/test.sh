sudo dmesg -C && 

make clean &&
make &&
clear &&

sudo insmod rootkit.ko &&

echo "" &&
cat /proc/net/tcp &&
echo "" &&

sudo rmmod rootkit &&

dmesg
