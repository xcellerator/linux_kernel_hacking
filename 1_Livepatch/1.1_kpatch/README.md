# Linux Kernel Hacking

## 1.1: Kpatch Example

In order to patch existing kernel functions, you have to be able to resolve relocatable symbols in the currently running kernel. Doing this manually would be very difficult and time-consuming, so [kpatch](https://github.com/dynup/kpatch) was created.

Kpatch works by first building the kernel tree normally, then rebuilding it with a patch provided as a source diff. Next, it takes the object files that changed, and rebuilds them again (both with and without the patch) with the GCC options `-ffunction-sections` and `-fdata-sections`. These two options cause all functions and data items to get their own sections, so that they can be found more easily without having to know precise offsets. Now the ELF relocation table can be built for the patched object file, and the kernel module is generated.

Setting up kpatch:
* `apt install dpkg-dev devscripts elfutils ccache`
* `apt build-dep linux`
* `git clone git@github.com:dynup/kpatch.git`
* `cd kpatch; make install`
* Download the debug kernel image from [http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/](http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/). The file you need is called `linux-image-unsigned-<KERNEL VERSION>-generic-dbgsym_<KERNEL VERSION>_amd64.ddeb`
* Install with `dpkg -i <path to .ddeb>`

To use:
* Check the output of `grep -i vmallocchunk /proc/meminfo`
* Build with `kpatch-build -t vmlinux --vmlinux /lib/debug/boot/vmlinux-$(uname -r) meminfo-string.patch`
* Load the kernel module with `insmod livepatch-meminfo-string.ko`
* Check the output of `grep -i vmallocchunk /proc/meminfo` again - notice that it's now in all-caps
* Disable the livepatch with `echo 0 | sudo tee /sys/kernel/livepatch/livepatch-meminfo-string/enabled`
* Unload from the kernel with `rmmod livepatch-meminfo-string.ko`

> Tested on Ubuntu 20.04 running under Vagrant.
> Helful Source: [https://ruffell.nz/programming/writeups/2020/04/20/everything-you-wanted-to-know-about-kernel-livepatch-in-ubuntu.html](https://ruffell.nz/programming/writeups/2020/04/20/everything-you-wanted-to-know-about-kernel-livepatch-in-ubuntu.html).
