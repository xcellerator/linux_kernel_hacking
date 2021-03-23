# Linux Kernel Hacking

## 3.5: Hiding processes

This module simply combines the syscall hooks for `sys_kill` from [Section 3.2](../3.2_kill_signalling) and `sys_getdents64` from [Section 3.4](../3.4_hiding_directories). The idea is that, when we intercept a signal `64` being sent to a `pid`, we store the pid in a global variable so the `sys_getdents64` hook can see it. Then, we simply hide any file/directory with a name that matches that pid.

> Note: In theory, someone might have a file/folder that happens to match that of a current pid on their system, that also happens to be the pid that we want to hide. The chances of this are slim, but I guess not impossible.

Almost all linux tools (including portions of the kernel!) use the contents of `/proc/` to lookup pids and any information associated to them. By virtue of "everything being a file" in linux, by hiding directory entries that match our pid's numerical value, we effectively hide the entire process from the operating system!

> Note: In the interest of avoiding clutter, I removed all the comments from the syscall hooks, and added a few comments relevant to hiding processes. For better explanations of what the syscall hooks are doing, line by line, see their sections linked in the top paragraph.

To use:
* Build with `make`
* Load with `insmod rootkit.ko`
* Get a list of running processes, e.g. `ps`, and pick a pid from the list
* Send signal `64` to the pid you chose, e.g. `kill -64 999`
* Check the output of `ps` again and see that your pid is missing!
* Unload with `rmmod rootkit`

> Note: Currently, only a single pid at a time can be hidden! Trying to hide another pid will work fine, but it will reveal the first one!

> Inspired, in part, by the [Diamorphine](https://github.com/m0nad/Diamorphine) repo.
