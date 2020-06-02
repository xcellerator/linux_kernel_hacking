# Linux Kernel Hacking

## 0.0: Basic LKM Example

This is about as simple as it gets.

To use:
* Build with `make`
* Load with `insmod example.ko`
* Check output in kernel buffer with `dmesg`
* See the module loaded in `lsmod | grep example`
* Unload with `rmmod example.ko`
* Check the second output in the kernel buffer with `dmesg`
