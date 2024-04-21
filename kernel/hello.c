#include <linux/types.h>
#include <linux/cred.h>
#include <linux/stddef.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/current.h>
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>


#define DEVICE_NAME "kernel_hack"

static int dispatch_open(struct inode *node, struct file *file)
{
	return 0;
}

static int dispatch_close(struct inode *node, struct file *file)
{
	return 0;
}

static long dispatch_ioctl(struct file *const file, unsigned int const cmd,
			   unsigned long const arg)
{
return 0;
}
static struct file_operations dispatch_functions = {
	.owner = THIS_MODULE,
	.open = dispatch_open,
	.release = dispatch_close,
	.unlocked_ioctl = dispatch_ioctl,
};

static struct miscdevice misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &dispatch_functions,
};


static int __init driver_entry(void)
{
	int ret;
	printk("[+] driver_entry");
	ret = misc_register(&misc);
	return ret;
}

static void __exit driver_unload(void)
{
	printk("[+] driver_unload");
	misc_deregister(&misc);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("Linux Kernel H4cking.");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Enen");
