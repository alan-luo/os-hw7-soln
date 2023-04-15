/*
 * farfetch.c
 */
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/highmem.h>

enum {
	FAR_READ,
	FAR_WRITE,
};

static long farfetch(unsigned int cmd, void __user *addr, struct pid *pid_struct,
	             unsigned long target_addr, size_t len)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	struct page **pages;
	void __user *iter;
	int locked;
	long ret;
	int i;
	unsigned long nr_pages;
	size_t page_off = target_addr & ~PAGE_MASK;

	/*
	 * handle overflow cases to be hyper-correct:
	 * - MAX_RW_COUNT check ensures we don't overflow into errno values
	 * - SIZE_MAX check ensures we don't overflow in nr_pages calculation
	 */
	len = min3(len, MAX_RW_COUNT, SIZE_MAX - page_off - PAGE_SIZE + 1);
	nr_pages = (page_off + len + PAGE_SIZE - 1) / PAGE_SIZE;
	WARN_ON(nr_pages * PAGE_SIZE < len);

	if (!pid_struct)
		return -ESRCH;
	tsk = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!tsk)
		return -ESRCH;

	mm = get_task_mm(tsk);
	put_task_struct(tsk);
	if (!mm)
		return -ESRCH;

	pages = kmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (pages == NULL) {
		mmput(mm);
		return -ENOMEM;
	}

	/*
	 * dealing with 'locked' allows get_user_pages_remote() to retry a fault
	 * if need be, but this isn't strictly necessary for our use cases
	 * (passing NULL would be fine)
	 */
	locked = 1;
	if (mmap_read_lock_killable(mm)) {
		mmput(mm);
		kfree(pages);
		return -EINTR;
	}
	ret = get_user_pages_remote(mm, target_addr, nr_pages,
				    (cmd == FAR_WRITE ? FOLL_WRITE : 0) | FOLL_FORCE,
				    /* (cmd == FAR_WRITE ? 0 : 0) | FOLL_FORCE, */
				    pages, NULL, &locked);
	if (locked)
		mmap_read_unlock(mm);
	mmput(mm);
	if (IS_ERR_VALUE(ret)) {
		kfree(pages);
		return ret;
	}

	if (ret < nr_pages) {
		nr_pages = ret;
		WARN_ON((nr_pages * PAGE_SIZE) - page_off > len);
		len = (nr_pages * PAGE_SIZE) - page_off;
	}

	ret = 0;
	iter = addr;
	for (i = 0; i < nr_pages; ++i) {
		size_t to_copy = min(len - (iter - addr), PAGE_SIZE - page_off);

		switch (cmd) {
		/*
		 * page_address()/page_to_virt() work as well as kmap() for our
		 * real-world use cases (using 64-bit systems), but we use the
		 * latter to be hyper-correct and account for highmem
		 */
		case FAR_READ:
			if (copy_to_user(iter, kmap(pages[i]) + page_off, to_copy))
				ret = -EFAULT;
			kunmap(pages[i]);
			break;
		case FAR_WRITE:
			if (copy_from_user(kmap(pages[i]) + page_off, iter, to_copy))
				ret = -EFAULT;
			else
				set_page_dirty_lock(pages[i]);
			kunmap(pages[i]);
			break;
		default:
			ret = -EINVAL;
		}
		if (ret)
			break;

		page_off = 0;
		iter += to_copy;
	}
	WARN_ON(!ret && iter - addr != len);

	for (i = 0; i < nr_pages; ++i)
		put_page(pages[i]);
	kfree(pages);

	return ret ? ret : len;
}

static ssize_t dev_read(struct file *fp, char __user *buf, size_t n, loff_t *of)
{
	long ret = farfetch(FAR_READ, buf, fp->private_data, *of, n);
	if (!(ret < 0))
		*of += ret;
	return ret;
}

static ssize_t dev_write(struct file *fp, const char __user *buf, size_t n,
			 loff_t *of)
{
	long ret = farfetch(FAR_WRITE, (void __user *)buf, fp->private_data, *of, n);
	if (!(ret < 0))
		*of += ret;
	return ret;
}

static int dev_open(struct inode *ino, struct file *fp)
{
	if (!try_module_get(THIS_MODULE))
		return -ENXIO;
	if (iminor(ino) != 0) {
		fp->private_data = find_get_pid(iminor(ino));
		if (fp->private_data == NULL)
			return -ESRCH;
	} else
		fp->private_data = NULL;
	return 0;
}

static int dev_release(struct inode *ino, struct file *fp)
{
	put_pid(fp->private_data);
	module_put(THIS_MODULE);
	return 0;
}

static long dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg)
{
	if (iminor(file_inode(fp)) != 0)
		return -ENOTTY;
	put_pid(fp->private_data);
	fp->private_data = find_get_pid(arg);
	if (fp->private_data == NULL)
		return -ESRCH;
	return 0;
}

static struct file_operations fops = {
	.llseek = default_llseek,
	.read = dev_read,
	.write = dev_write,
	.open = dev_open,
	.release = dev_release,
	.unlocked_ioctl = dev_ioctl,
};

static int major;

int farfetch_init(void)
{
	pr_info("Installing farfetch\n");
	major = __register_chrdev(0, 0, MINORMASK + 1, "farfetch", &fops);
	if (major < 0) {
		pr_err("register_chrdev %d", major);
		return major;	
	}
	return 0;
}

void farfetch_exit(void)
{
	pr_info("Removing farfetch\n");
	__unregister_chrdev(major, 0, MINORMASK + 1, "farfetch");
}

module_init(farfetch_init);
module_exit(farfetch_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("farfetch: for fetching pages from afar");
MODULE_AUTHOR("Kent Hall");
