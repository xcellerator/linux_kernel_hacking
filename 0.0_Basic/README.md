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

Alternatively:
* Run `make test` and observe the two outputs as the module is loaded/unloaded.

> NOTE: You'll need `build-essential` and `linux-headers-$(uname -r)` installed.

> Followed along from [here](https://blog.sourcerer.io/writing-a-simple-linux-kernel-module-d9dc3762c234?gi=2f8d0507c4e8).
