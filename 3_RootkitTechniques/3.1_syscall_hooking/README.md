# Linux Kernel Hacking

## 3.1: Syscall Table Hijacking

Hijacking the linux syscall table, and hooking `sys_mkdir`.

We have to use the `pt_regs` struct defined in [`arch/x86/include/asm/ptrace.h`](https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/ptrace.h) in order to be able to access the argument passed to the syscall in our hook. Crucially, we have to define `orig_mkdir` via:

```C
typedef asmlinkage long (*orig_mkdir_t)(const struct pt_regs *);
orig_mkdir_t orig_mkdir;
```

This means that we can wrap around this syscall by doing whatever we want to do in our hook, and then just pass the entire `pt_regs` struct over to this function pointer with `orig_mkdir(regs)` when we're done.

The other benefit of doing this is that we only have to extract the arguments that we are interested in and not all of them solely for the purpose of passing them along to the real syscall. Looking up `sys_mkdir` [here](https://syscalls64.paolostivanin.com/), we see that `*pathname` is stored in the `rdi` register. This means that we simply dereference the string containing the new directory with `(char *)regs->di`.

To use:
* Build with `make`
* Load with `insmod rootkit.ko`
* Create a directory with `mkdir a`
* Check output in kernel buffer with `dmesg`
* Unload with `rmmod rootkit`
