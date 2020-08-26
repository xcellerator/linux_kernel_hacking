# Linux Kernel Hacking

## 3.4: Hiding files/directories

> Updated to use [ftrace](https://www.kernel.org/doc/html/latest/trace/ftrace.html) instead of directly modifying kernel memory

> Sadly, this module is a lot bigger when we use ftrace. The reason is that we end up repeating the hook function *four* times - two copies each of both `sys_getdents` and `sys_getdents64`, using both the `pt_regs` struct and the old-fashioned function declaration (for kernel versions <4.17 - looking at you Ubuntu 16.04...)

This is probably the most complicated syscall hook yet. As far as the kernel module goes, the structure is the same as the others in this section - we find the syscall table, and then hook a syscall with our own replacement, in this case, we hook `sys_getdents64`.

What makes this task more difficult is that we are actually altering the structs that are returned to the user. First, we extract the *userspace* `dirent` struct from the `si` register in `regs`, and then call the real `sys_getdents64` and save the result in `ret`. Then, we have to `copy_from_user` the *userspace* `dirent` struct to the *kernelspace* `dirent_ker` struct so that we can probe and alter it's contents. At this point, we loop through the directory entries using `offset` (initially set to `0`, and incremented by the `d_reclen` field of each dirent as we proceed through the entries).

As we come to each entry, we compare the `d_name` field to `PREFIX` (defined to be "boogaloo") and, if we get a match, we increment the `d_reclen` field of the *previous* entry by that of the current one. This results in the current entry being completely skipped over by anything that interates blindly over these entries (as essentially everything does!).

The only caveat is if "boogaloo" appears in the *first* entry in the list, i.e. there is no previous entry that can subsume this one. The remedy to this circumstance is to just subtract from `ret` the `d_reclen` of the current (first) entry, and `memmove` everything *after* the first entry up to the start of the entry structure.

Finally, we just have to `copy_to_user` the `dirent_ker` struct back to the userspace `dirent` one and return `ret` back to the user.

To use:
* Build with `make`
* Create a file/directory that starts with the string "boogaloo", e.g. `touch boogaloo`
* Load with `insmod rootkit.ko`
* List the directory contents of wherever you placed the "boogaloo" file, e.g. `ls`
* Observe that the "boogaloo" file is missing!
* Unload with `rmmod rootkit`
