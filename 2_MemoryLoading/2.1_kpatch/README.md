# Linux Kernel Hacking

## 2.0: Loading a Kernel Module from Memory (Kpatch)

Patch the kernel with a single executable!

To use:
* Set up kpatch following [these](../2.0_no_arguments/) instructions.
* Build the patch with `kpatch-build -t vmlinux -v /lib/debug/boot/vmlinux-<KERNEL>-generic chown.patch`
* Remove the `-` from the filename (C doesn't like it in variable names)
  * `mv livepatch-chown.ko livepatch_chown.ko`
* Build the loader with `make`
* Execute as root with `sudo ./load`
* `chown` a file, e.g. `chown vagrant:vagrant chown.patch`
* Check output in kernel buffer with `dmesg`
* Unload with `echo 0 | sudo tee /sys/kernel/livepatch/chown/enabled && sudo rmmod chown`
