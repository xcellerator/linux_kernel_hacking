# Linux Kernel Hacking

## 3.3: Custom Signals To Give Root Privileges To A Process

Similar to [Section 3.2](../3.2_kill_signalling/), we can abuse hooking `sys_kill` to trigger a function that gives root to any process that sends a `64` signal to a process (as before, signal `64` is normally unused).

According to [credentials.rst](https://github.com/torvalds/linux/blob/master/Documentation/security/credentials.rst#altering-credentials), we can only modify the `cred` struct of our own process, and not that of any other process. This means that we can't give an already running process root privileges unless we send the `64` signal from that process! Quite a clever security feature!

All we have to do is send signal `64` to any process (as before, the signal isn't actually sent anywhere!) and we end up being root!

To use:
* Build with `make`
* Load with `insmod rootkit.ko`
* Confirm that you currently are *not* root with `whoami`
* Send signal `64` to any pid, e.g. `kill -64 1`
  * Note that the signal won't actually be sent to the pid you specify, so any number will do!
* Check `whoami` again, and observe that you are now root!
* Unload with `rmmod rootkit`
