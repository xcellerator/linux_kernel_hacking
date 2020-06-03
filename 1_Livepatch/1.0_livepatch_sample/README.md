# Linux Kernel Hacking

## 1.0: Livepatch

Patching kernel functions in memory on a live machine. Taken from [samples/livepatch](https://github.com/torvalds/linux/tree/master/samples/livepatch).

This livepatch kernel module creates a replacement for `cmdline_proc_show()` from [`fs/proc/cmdline.c`](https://github.com/torvalds/linux/blob/master/fs/proc/cmdline.c) to simply print a message out instead of the usual cmdline.

To use:
* Check the output of `cat /proc/cmdline`
* Build with `make`, and load into the kernel with `insmod livepatch-sample.ko`
* Check the output again of `cat /proc/cmdline`
* Disable the livepatch with `echo 0 | sudo tee /sys/kernel/livepatch/livepatch-sample/enabled`
* Unload from the kernel with `rmmod livepatch-sample.ko`

> Tested on Ubuntu 20.04 running under Vagrant.
