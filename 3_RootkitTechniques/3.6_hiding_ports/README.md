# Linux Kernel Hacking

## 3.6: Hiding open ports (8080)

Most linux applications that search for local open ports (netstat included) use the `/proc/net/tcp` pseudo-file to do so. In particular, parsing this file is handled by `tcp4_seq_show` in [`net/ipv4/tcp_ipv4.c`](https://github.com/torvalds/linux/blob/a1d21081a60dfb7fddf4a38b66d9cef603b317a9/net/ipv4/tcp_ipv4.c#L2600). By hooking this function, we can choose to hide a particular open port from userspace.

However, hooking a kernel function is nowhere near as simple as hooking a syscall. Syscalls are easy because we just look up the memory address of the syscall table and modify the corresponding entry to point a different function that we control. While `tcp4_seq_show` does indeed appear in `/proc/kallsymms` (which means we can use `kallsyms_lookup_name()` again), we don't have anything to modify because the address returned is the function pointer itself, rather than a pointer to a pointer!

The solution is to use [ftrace](https://www.kernel.org/doc/html/latest/trace/ftrace.html). While it's meant to be used for debugging the kernel, we can use it to replace the `tcp4_seq_show` function in memory with a hook instead. If you want to understand what's going on with ftrace, then I suggest taking a look at the documentation linked. There's a bunch of helper functions in [`ftrace_helper.h`](./ftrace_helper.h), so that we can focus on the actual function hook in [`rootkit.c`](./rootkit.c).

As far as the function hooking goes, it's quite simple. We give a function declaration for the original `tcp4_seq_show()`, then we define the function `hook_tcp4_seq_show()`. This hook simply checks to see if the local port number given by `sk->sk_num` is 8080 (`0x1f90` in hex), and if so it just returns `0`. Otherwise, we go ahead and pass the given arguments to the real `tcp4_seq_show()`. Note that because we aren't hook a syscall this time, we don't have to worry about `pt_regs` because the arguments are passed on the stack rather than in registers!

Then, we define the `hooks` array which contains `ftrace_hook` structs containing the name, hook function address and original function address. If we wanted to, we could add more hooks to this array and, as long as the original and hook functions are defined as for `tcp4_seq_show()`, they would be hooked alongside. Once we enter the module initialization function, we just call the `fh_install_hooks()` function defined in [`ftrace_helper.h`](./ftrace_helper.h) and pass the `hooks` array to it. This does all the heavy lifting for us. Likewise, when module exit function gets called, we just call the `fh_remove_hooks()` function.

To use:
* Build with `make`
* Load with `insmod rootkit.ko`
* In another terminal, create a netcat listener on port 8080 with `nc -lvnp 8080`
* Check all the open local ports with `netstat -tunelp`
* Observe that port 8080 is *not* listed!
* Unload with `rmmod rootkit`
* Check the output of `netstat -tunelp` again and see that port 8080 now shows up!
