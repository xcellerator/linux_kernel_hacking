# Linux Kernel Hacking

## 3.0: Hiding Kernel Modules

Hide a kernel module after loading it

To use:
* Build with `make`
* Load with `insmod rootkit.ko`
* Check output in kernel buffer with `dmesg`
* See that the module is missing from the output of `lsmod`

> NOTE: Currently, you can't unload this kernel module without rebooting
