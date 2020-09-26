obj-m += escape.o
kmod_name = escape

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	echo "#include <linux/module.h>" > tmp.c
	echo "#include <syscall.h>" >> tmp.c
	echo "#include <stdio.h>" >> tmp.c
	echo "" >> tmp.c
	xxd -i $(kmod_name).ko >> tmp.c
	echo "const char args[] = \"\\\0\";" >> tmp.c
	echo "" >> tmp.c
	cat stub.c >> tmp.c
	cat tmp.c | sed 's/example_ko/$(kmod_name)_ko/g' > load.c
	rm tmp.c
	gcc -o escape load.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	gcc -o execute execute.c
	rm load.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm execute escape
