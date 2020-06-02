# Linux Kernel Hacking

## 0.0: Basic LKM Example

This is about as simple as it gets.

To use:
* Build with `make` and load with `make test`
* Create a device file with `mknod /dev/example c <MAJOR> 0`, replacing `<MAJOR>` with major number returned in the kernel buffer.
* Take a look at the device with `cat /dev/example`
* Delete the device file with `rm /dev/example` and unload the module with `rmmod example`

> Followed along from [here](https://blog.sourcerer.io/writing-a-simple-linux-kernel-module-d9dc3762c234?gi=2f8d0507c4e8).
