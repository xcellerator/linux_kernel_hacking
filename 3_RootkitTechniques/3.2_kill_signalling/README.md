# Linux Kernel Hacking

## 3.2: Custom Signals To Hide/Reveal LKMs

We can use the same syscall hijacking method from [Section 3.1](../3.1_syscall_hooking/) to hijack the `sys_kill` syscall rather than `sys_mkdir`. This lets us implement our own custom signals to call different functions within the rootkit. In this case, we use signal `64` (normally unused) to tell the module hide or unhide itself (using the `hideme()` and `showme()` functions from [Section 3.0](../3.0_hiding_lkm/)).

> NOTE: While experimenting with this module, I found that the kernel kept panicking and crashing if I probed the calls to `sys_mkdir` too often, i.e. trying to `printk` every call signal send to every pid. I think this is probably something to do with a race condition somewhere, but I'm not certain.

To use:
* Build with `make`
* Load with `insmod rootkit.ko`
* Send signal `64` to any pid, e.g. `kill -64 1`
  * Note that the signal won't actually be sent to the pid you specify, so any number will do!
* Observe the `rootkit` is missing from the output of `lsmod`
  * While the module is hidden, you will be unable unload it!
* Send signal `64` to any pid again e.g. `kill -64 1'
* Observe that the `rootkit` is back in the output of `lsmod`
* Unload with `rmmod rootkit`
