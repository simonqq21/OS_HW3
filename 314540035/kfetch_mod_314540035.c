#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/cpumask.h> // CPU counts
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h> // total RAM, free RAM, process count, uptime
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/printk.h>

#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/sched/stat.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/time_namespace.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/utsname.h> // kernel release
#include <linux/version.h>

#include <linux/sched/signal.h> // Required for for_each_process

#include <asm/errno.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("simonqq21");
MODULE_DESCRIPTION("kfetch fetches system information.");

#define KFETCH_NUM_INFO 6

#define KFETCH_RELEASE (1 << 0)
#define KFETCH_NUM_CPUS (1 << 1)
#define KFETCH_CPU_MODEL (1 << 2)
#define KFETCH_MEM (1 << 3)
#define KFETCH_UPTIME (1 << 4)
#define KFETCH_NUM_PROCS (1 << 5)

#define KFETCH_FULL_INFO ((1 << KFETCH_NUM_INFO) - 1)

/*
Function prototypes
*/
static ssize_t kfetch_read(struct file *,
						   char __user *,
						   size_t,
						   loff_t *);
static ssize_t kfetch_write(struct file *,
							const char __user *,
							size_t,
							loff_t *);
static int kfetch_open(struct inode *, struct file *);
static int kfetch_release(struct inode *, struct file *);

#define DEVICE_NAME "kfetch"
#define BUF_LEN 1024
#define LINE_BUF_LEN 256

static int major;
/* Is device open? Used to prevent multiple access to device */
static DEFINE_MUTEX(device_mutex);

/*message buffer*/
static char kbuf[BUF_LEN + 1] = "\0";
static char linebuf[LINE_BUF_LEN];
static unsigned int mask_info = KFETCH_FULL_INFO;

static struct class *cls;
// tux logo
static const char logo[7][20] =
	{
		"        .-.        ",
		"       (.. |       ",
		"       <>  |       ",
		"      / --- \\      ",
		"     ( |   | )     ",
		"   |\\\\_)__(_//|    ",
		"  <__)------(__>   ",
};

struct sysinfo si;
struct new_utsname *uts;
char hostname[128];
unsigned int cpus_online;
unsigned int cpus_total;
unsigned long mem_total_mb;
unsigned long mem_free_mb;
unsigned long mem_used_mb;
unsigned long mem_available_pages;
unsigned long mem_available_mb;
struct task_struct *task;
unsigned int num_procs = 0;
struct timespec64 uptime;
unsigned long uptime_mins;
char cpu_model[64];

static const struct file_operations kfetch_ops = {
	.owner = THIS_MODULE,
	.read = kfetch_read,
	.write = kfetch_write,
	.open = kfetch_open,
	.release = kfetch_release,
};

static int __init kfetch_init(void)
{
	major = register_chrdev(0, DEVICE_NAME, &kfetch_ops);
	if (major < 0)
	{
		pr_alert("Kfetch: Registering char device failed with %d\n.", major);
		return major;
	}
	pr_info("Kfetch: Assigned major number %d.\n", major);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	cls = class_create(DEVICE_NAME);
#else
	cls = class_create(THIS_MODULE, DEVICE_NAME);
#endif

	device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
	pr_info("Device created on /dev/%s\n", DEVICE_NAME);
	return 0;
}

static void __exit kfetch_exit(void)
{
	device_destroy(cls, MKDEV(major, 0));
	class_destroy(cls);
	unregister_chrdev(major, DEVICE_NAME);
	pr_info("Device kfetch has been unregistered.\n");
}

// open operation
static int kfetch_open(struct inode *inode, struct file *file)
{
	if (mutex_lock_interruptible(&device_mutex))
	{
		return -ERESTARTSYS;
	}
	return 0;
}

// release operation
static int kfetch_release(struct inode *inode, struct file *file)
{
	mutex_unlock(&device_mutex);

	return 0;
}

static ssize_t kfetch_read(struct file *file,
						   char __user *ubuf,
						   size_t length,
						   loff_t *offset)
{
	/* fetching the information */
	// get info
	si_meminfo(&si);
	uts = utsname();
// CPU model
#ifdef __x86_64
	struct cpuinfo_x86 *c = &boot_cpu_data;
	if (c->x86_model_id[0])
	{
		strcpy(cpu_model, c->x86_model_id);
	}
	else
	{
		strcpy(cpu_model, "RISC-V Processor");
	}
#else
	strcpy(cpu_model, "RISC-V Processor");
#endif

	// CPU cores
	cpus_online = num_online_cpus();
	cpus_total = num_possible_cpus();
	// memory
	mem_available_pages = si_mem_available();
	mem_total_mb = si.totalram * si.mem_unit / 1024 / 1024;
	mem_available_mb = mem_available_pages * PAGE_SIZE / 1024 / 1024;
	mem_used_mb = mem_total_mb - mem_available_mb;
	// process count
	num_procs = 0;
	rcu_read_lock(); // Lock to ensure the list doesn't change while we read
	for_each_process(task)
	{
		num_procs++;
	}
	rcu_read_unlock(); // Unlock
	// uptime
	ktime_get_boottime_ts64(&uptime);
	timens_add_boottime(&uptime);
	uptime_mins = uptime.tv_sec / 60;

	// print output
	strcpy(kbuf, "");
	// hostname
	sprintf(linebuf, "                   %s\n", uts->nodename);
	strcat(kbuf, linebuf);
	sprintf(linebuf, "%s------------\n", logo[0]);
	strcat(kbuf, linebuf);
	// kernel release
	sprintf(linebuf, "%s", logo[1]);
	strcat(kbuf, linebuf);
	// pr_info("1 %d\n", mask_info & KFETCH_RELEASE);
	if (mask_info & KFETCH_RELEASE)
	{
		sprintf(linebuf, "Kernel: %s", uts->release);
		strcat(kbuf, linebuf);
	}
	sprintf(linebuf, "\n");
	strcat(kbuf, linebuf);
	// CPU model
	sprintf(linebuf, "%s", logo[2]);
	strcat(kbuf, linebuf);
	// pr_info("2 %d\n", mask_info & KFETCH_CPU_MODEL);
	if (mask_info & KFETCH_CPU_MODEL)
	{
		sprintf(linebuf, "CPU:    %s", cpu_model);
		strcat(kbuf, linebuf);
	}
	sprintf(linebuf, "\n");
	strcat(kbuf, linebuf);
	// CPU cores
	sprintf(linebuf, "%s", logo[3]);
	strcat(kbuf, linebuf);
	if (mask_info & KFETCH_NUM_CPUS)
	{
		sprintf(linebuf, "CPUs:   %d / %d", cpus_online, cpus_total);
		strcat(kbuf, linebuf);
	}
	sprintf(linebuf, "\n");
	strcat(kbuf, linebuf);
	// memory
	sprintf(linebuf, "%s", logo[4]);
	strcat(kbuf, linebuf);
	if (mask_info & KFETCH_MEM)
	{
		sprintf(linebuf, "Mem:    %lu / %lu MB", mem_used_mb, mem_total_mb);
		strcat(kbuf, linebuf);
	}
	sprintf(linebuf, "\n");
	strcat(kbuf, linebuf);
	// process count
	sprintf(linebuf, "%s", logo[5]);
	strcat(kbuf, linebuf);
	if (mask_info & KFETCH_NUM_PROCS)
	{
		sprintf(linebuf, "Procs:  %u", num_procs);
		strcat(kbuf, linebuf);
	}
	sprintf(linebuf, "\n");
	strcat(kbuf, linebuf);
	// uptime
	sprintf(linebuf, "%s", logo[6]);
	strcat(kbuf, linebuf);
	if (mask_info & KFETCH_UPTIME)
	{
		sprintf(linebuf, "Uptime: %lu mins", uptime_mins);
		strcat(kbuf, linebuf);
	}
	sprintf(linebuf, "\n");
	strcat(kbuf, linebuf);

	pr_info("%s\n", kbuf);

	int len = strlen(kbuf);
	ssize_t ret = len;
	pr_info("device read length %d\n", len);
	if (copy_to_user(ubuf, kbuf, len))
	{
		pr_alert("/dev/kfetch: read error\n");
		return -EINVAL;
	}
	if (*offset >= len)
	{
		ret = 0;
	}
	*offset += len;
	return ret;
}

static ssize_t kfetch_write(struct file *file,
							const char __user *ubuf,
							size_t length,
							loff_t *offset)
{

	unsigned long buf_size = length;
	if (buf_size >= BUF_LEN)
		buf_size = buf_size - 1;

	if (copy_from_user(&mask_info, ubuf, sizeof(mask_info)))
	{
		pr_alert("/dev/kfetch: write error\n");
		return -EFAULT;
	}

	if (mask_info < 0)
		mask_info = 0;
	if (mask_info > KFETCH_FULL_INFO)
		mask_info = KFETCH_FULL_INFO;
	pr_info("mask_info = %u\n", mask_info);

	*offset += sizeof(mask_info);
	return sizeof(mask_info);
}

module_init(kfetch_init);
module_exit(kfetch_exit);