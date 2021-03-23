# Linux Kernel Hacking

## 3.0: Hiding Kernel Modules

> Please check out the blog post for an in-depth explanation on how this module works. You can find it [here](https://xcellerator.github.io/posts/linux_rootkits_05/).

Hide a kernel module after loading it.

To use:
* Build with `make`
* Load with `insmod rootkit.ko`
* Check output in kernel buffer with `dmesg`
* See that the module is missing from the output of `lsmod`

> NOTE: Currently, you can't unload this kernel module without rebooting

> Inspired, in part, by the [Diamorphine](https://github.com/m0nad/Diamorphine) repo.
