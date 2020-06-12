# Linux Kernel Hacking

## 2.0: Loading a Kernel Module from Memory (No Arguments)

Load the [`example.ko`](../../0_Basic_LKMs/0.0_Basic/) kernel module from memory - *without using `insmod`*.

To use:
* Build with `make`
* Execute as root with `sudo ./load` 
* Check output in kernel buffer with `dmesg`
* See the module loaded in `lsmod | grep example`
* Unload with `rmmod example`
* Check the second output in the kernel buffer with `dmesg`

> NOTE: This assumes that `example.ko` is in the current directory. If your LKM is named something else, change the first line in the [`Makefile`](./Makefile).
