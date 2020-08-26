# Linux Kernel Hacking

## 3.6: Hiding open ports (8080)

Most linux applications that search for local open ports (netstat included) use the `/proc/net/tcp` pseudo-file to do so. In particular, parsing this file is handled by `tcp4_seq_show` in [`net/ipv4/tcp_ipv4.c`](https://github.com/torvalds/linux/blob/a1d21081a60dfb7fddf4a38b66d9cef603b317a9/net/ipv4/tcp_ipv4.c#L2600). By hooking this function, we can choose to hide a particular open port from userspace.

As far as the function hooking goes, it's quite simple. We give a function declaration for the original `tcp4_seq_show()`, then we define the function `hook_tcp4_seq_show()`. This hook simply checks to see if the local port number given by `sk->sk_num` is 8080 (`0x1f90` in hex), and if so it just returns `0`. Otherwise, we go ahead and pass the given arguments to the real `tcp4_seq_show()`.

Note that because we aren't hooking a syscall this time, we don't have to worry about `pt_regs` because the arguments are passed on the stack rather than in registers!

To use:
* Build with `make`
* Load with `insmod rootkit.ko`
* In another terminal, create a netcat listener on port 8080 with `nc -lvnp 8080`
* Check all the open local ports with `netstat -tunelp`
* Observe that port 8080 is *not* listed!
* Unload with `rmmod rootkit`
* Check the output of `netstat -tunelp` again and see that port 8080 now shows up!
