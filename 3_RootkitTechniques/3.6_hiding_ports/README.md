# Linux Kernel Hacking

## 3.6: Hiding open ports

> WORK IN PROGRESS

Most linux applications that search for local open ports (netstat included) use the `/proc/net/tcp` pseudo-file to do so. By hooking this function, we can choose to hide a particular open port from userspace.

To use:
* TBC
