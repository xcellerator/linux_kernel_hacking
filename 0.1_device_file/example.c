#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Example");
MODULE_DESCRIPTION("Device File Example");
MODULE_VERSION("0.01");

#define DEVICE_NAME "example"
#define EXAMPLE_MSG "Hello, World!\n"
#define MSG_BUFFER_LEN 15

/* Required prototypes */
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

static int major_num;
static int device_open_count = 0;
static char msg_buffer[MSG_BUFFER_LEN];
static char *msg_ptr;

/* Structure of all device functions */
static struct file_operations file_ops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release,
};

/* This function gets called whenever something reads from the device */
static ssize_t device_read(struct file *flip, char *buffer, size_t len, loff_t *offst)
{
	int bytes_read = 0;

	/* Loop indefinitely */
	if (*msg_ptr == 0)
		msg_ptr = msg_buffer;

	/* Load the buffer */
	while (len && *msg_ptr)
	{
		/* The buffer is in userspace, not kernel space, so
		 * we can't just use a normal dereference. The function
		 * put_user() handles moving data from the kernel, into
		 * userspace. */
		put_user(*(msg_ptr++), buffer++);
		len--;
		bytes_read++;
	}

	return bytes_read;
}

/* Ths function gets called whenever something tries to write to the device */
static ssize_t device_write(struct file *flip, const char *buffer, size_t len, loff_t *offset)
{
	/* Read-only, so just kick them out */
	printk(KERN_ALERT "This operation is not supported.\n");
	return -EINVAL;
}

/* This function is called whenever something tries to open the device */
static int device_open(struct inode *inode, struct file *file)
{
	/* If it's already open, return busy */
	if (device_open_count)
	{
		return -EBUSY;
	}
	device_open_count++;
	/* try_module_get() checks to see if the module is being removed,
	 * and if so, we need to act as if the module doesn't exist (more
	 * important when we reference other modules from this one). */
	try_module_get(THIS_MODULE);
	return 0;
}

/* This function is called whenever something tries to close the device */
static int device_release(struct inode *inode, struct file *file)
{
	/* Decrement the open counter and usage count, otherwise the module
	 * won't unload */
	device_open_count--;
	/* Alert the kernel that we are done using this module (for now).
	 * This will cause try_module_get() to return true, so that the
	 * module can be unloaded safely. */
	module_put(THIS_MODULE);
	return 0;
}

static int __init example_init(void)
{
	/* Fill buffer */
	strncpy(msg_buffer, EXAMPLE_MSG, MSG_BUFFER_LEN);
	/* Set msg_ptr to start of buffer */
	msg_ptr = msg_buffer;
	/* Register character device */
	major_num = register_chrdev(0, "example", &file_ops);
	if (major_num < 0)
	{
		printk(KERN_ALERT "Could not register device: %d\n", major_num);
		return major_num;
	}
	else
	{
		printk(KERN_INFO "example module loaded with device major number %d\n", major_num);
		return 0;
	}
}

static void __exit example_exit(void)
{
	/* Clean up */
	unregister_chrdev(major_num, DEVICE_NAME);
	printk(KERN_INFO "Goodbye, World!\n");
}

module_init(example_init);
module_exit(example_exit);
