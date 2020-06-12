kmod_name = example

all:
	echo "#include <linux/module.h>" > load.c
	echo "#include <syscall.h>" >> load.c
	echo "#include <stdio.h>" >> load.c
	echo "" >> load.c
	xxd -i $(kmod_name).ko >> load.c
	echo "const char args[] = \"\\\0\";" >> load.c
	echo "" >> load.c
	cat stub.c >> load.c
	gcc -o load load.c
