#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romain Kowalski");
MODULE_DESCRIPTION("A keylogger.");

#define MODULE_NAME "keylogger"
#define DEVICE_NAME "not_a_keylogger"

static struct file_operations	logs_fops {
	.read = &log_read,
	.write = &log_write
};

static struct miscdevice	logs_device {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &logs_fops
};

static int	__init kl_init(void)
{
	int	ret;

	ret = misc_register(&logs_device);
	if (ret)
		pr_err("Loading module %s failed (dunno why tho)\n",
								MODULE_NAME);
	else
		pr_info("Module %s loaded\n", MODULE_NAME);
	return (ret);
}

static void	__exit kl_cleanup(void)
{
	misc_deregister(&logs_device);
}
