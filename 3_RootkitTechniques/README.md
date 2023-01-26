# Linux Kernel Hacking

## 3: Rootkit Techniques

> Updated to work with kernel 5.7+

There are two main way to hook syscalls via a kernel module. The first, old-fashioned way is to directly modify the `sys_call_table` structure in kernel memory. This is done by modifying the function pointer in this table corresponding to the syscall we're targetting to temporarily point to our own version. By saving the original value of this pointer we can both maintain the original functionality as well as restore the table when we're done. This is what is done in [Section 3.1](./3.1_syscall_hooking).

The other more modern method is to use [ftrace](https://www.kernel.org/doc/html/latest/trace/ftrace.html). While it's meant to be used for debugging the kernel, we can use it to replace the arbitrary functions in memory with a hook instead. If you want to understand in detail what's going on with ftrace, then I suggest taking a look at the documentation linked.

As far as the function hooking goes, it's quite simple. We give a function declaration for the original function, then we write the function hook. Then, we define the `hooks` array which contains `ftrace_hook` structs containing the name, hook function address and original function address. Once we enter the module initialization function, we just call the `fh_install_hooks()` function defined in `ftrace_helper.h` and pass the `hooks` array to it. This does all the heavy lifting for us. Likewise, when module exit function gets called, we just call the `fh_remove_hooks()` function.

#### References/Further Reading

* [Diamorphine](https://github.com/m0nad/Diamorphine)
* [Reptile](https://github.com/f0rb1dd3n/Reptile)
* [Ftrace](https://github.com/ilammy/ftrace-hook)
* [EXEC-LKM](https://github.com/loneicewolf/EXEC_LKM)
