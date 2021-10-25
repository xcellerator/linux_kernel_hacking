# Linux Kernel Hacking

## 3.10: Hiding open ports (8080)

To use:
* Build with `make`
* Load with `insmod rootkit.ko`
* In another terminal, create a netcat listener on port 8080 with `nc -lvnp 8080`
* Check all the open local ports with `ss -tuna`
* Observe that port 8080 is *not* listed!
* Unload with `rmmod rootkit`
* Check the output of `ss -tuna` again and see that port 8080 now shows up!
