#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mutex.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romain Kowalski");
MODULE_DESCRIPTION("Absolutely not a keylogger.");

#define MODULE_NAME "not_a_keylogger"
#define DEVICE_NAME "definitely_not_key_logs"

static struct	key_stroke {
	unsigned int		key_code;
	bool			key_status; // 1 = pressed, 0 = released
	ktime_t			time;
};

static size_t			capture_size = 0;
static struct key_stroke	*captured_keys = NULL;
static char			*log_file = NULL;
static struct mutex		log_mutex;

static ssize_t 	logs_read(struct file *filp, char __user *buffer, size_t len,
							loff_t *offset)
{
	pr_info("read");
	return (0);
}

static int	logs_open(struct inode *inode, struct file *file)
{
	pr_info("Log file opened");
	try_module_get(THIS_MODULE);
	return (0);
}

static int	logs_close(struct inode *inode, struct file *file)
{
	pr_info("Log file closed");
	module_put(THIS_MODULE);
	if (module_refcount(THIS_MODULE) == 0)
	{
		mutex_lock(&log_mutex);
		kfree(log_file);
		log_file = NULL;
		capture_size = 0;
		mutex_unlock(&log_mutex);
	}
	return (0);
}

static struct file_operations	logs_fops = {
	.open = &logs_open,
	.release = &logs_close,
	.read = &logs_read,
};

static struct miscdevice	logs_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &logs_fops
};

static int	__init kl_init(void)
{
	int	ret;

	ret = misc_register(&logs_device);
	if (ret)
		pr_err("Loading module %s failed\n", MODULE_NAME);
	else
		pr_info("Module %s loaded\n", MODULE_NAME);
	return (-ret);
}

static void	__exit kl_cleanup(void)
{
	misc_deregister(&logs_device);
	kfree(log_file);
	kfree(captured_keys);
	pr_info("Module %s unloaded\n", MODULE_NAME);
}

module_init(kl_init);
module_exit(kl_cleanup);
