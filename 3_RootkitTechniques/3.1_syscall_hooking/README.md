# Linux Kernel Hacking

## 3.1: Syscall Table Hijacking

Hijacking the linux syscall table, and hooking `sys_mkdir`.

To use:
* Build with `make`
* Load with `insmod rootkit.ko`
* Create a directory with `mkdir a`
* Check output in kernel buffer with `dmesg`
* Unload with `rmmod rootkit`
