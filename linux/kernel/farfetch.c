#include <linux/syscalls.h>
#include <linux/printk.h>

long farfetch_default(unsigned int cmd, void __user *addr, pid_t target_pid,
		      unsigned long target_addr, size_t len)
{
	pr_err("farfetch module not inserted.\n");
	return -ENOSYS;
}

long (*farfetch_ptr)(unsigned int cmd, void __user *addr, pid_t target_pid,
		     unsigned long target_addr, size_t len) = farfetch_default;

SYSCALL_DEFINE5(farfetch, unsigned int, cmd, void __user *, addr,
			  pid_t, target_pid, unsigned long, target_addr,
			  size_t, len)
{
	return farfetch_ptr(cmd, addr, target_pid, target_addr, len);
}

EXPORT_SYMBOL(farfetch_default);
EXPORT_SYMBOL(farfetch_ptr);
