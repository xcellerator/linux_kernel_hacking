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

> NOTE: If you aren't running kernel `5.4.0-33-generic` (Ubuntu 20.04 currently), then you will need to recompile [`example.ko`](../../0_Basic_LKMs/0.0_Basic/), and replace the `example_ko` and `example_ko_len` lines with the output of `xxd -i example.ko`.
