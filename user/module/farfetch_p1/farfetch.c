#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/highmem.h>
#include <linux/farfetch.h>

extern long (*farfetch_ptr)(unsigned int cmd, void __user *addr,
			    pid_t target_pid, unsigned long target_addr,
			    size_t len);
extern long farfetch_default(unsigned int cmd, void __user *addr,
			     pid_t target_pid, unsigned long target_addr,
			     size_t len);

long farfetch(unsigned int cmd, void __user *addr, pid_t target_pid,
	      unsigned long target_addr, size_t len)
{
	struct pid *pid_struct;
	struct task_struct *tsk;
	struct mm_struct *mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;
	long err;
	size_t page_off = target_addr & ~PAGE_MASK;

	if (from_kuid_munged(current_user_ns(), task_euid(current)))
		return -EPERM;

	pid_struct = find_get_pid(target_pid);
	tsk = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!tsk)
		return -ESRCH;

	if (!(target_addr < TASK_SIZE_OF(tsk))) {
		put_task_struct(tsk);
		return -EFAULT;
	}

	mm = get_task_mm(tsk);
	put_task_struct(tsk);
	if (!mm)
		return -ESRCH;

	if (mmap_read_lock_killable(mm)) {
		mmput(mm);
		return -EINTR;
	}

	err = -EFAULT;
	pgd = pgd_offset(mm, target_addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto walk_end;

	p4d = p4d_offset(pgd, target_addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		goto walk_end;

	pud = pud_offset(p4d, target_addr);
	if (pud_none(*pud) || pud_bad(*pud))
		goto walk_end;

	pmd = pmd_offset(pud, target_addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd) || !pmd_present(*pmd))
		goto walk_end;

	/* in case PTE is in high memory */
	ptep = pte_offset_map(pmd, target_addr);
	if (!ptep)
		goto walk_end;
	pte = *ptep;
	pte_unmap(ptep);

	if (pte_none(pte) || !pte_present(pte) ||
	    (cmd == FAR_WRITE && !pte_write(pte)))
		goto walk_end;

	get_page(pte_page(pte));
	err = 0;

walk_end:
	mmap_read_unlock(mm);
	mmput(mm);
	if (err)
		return err;

	len = min(PAGE_SIZE - page_off, len);
	switch (cmd) {
	/*
	 * page_address()/page_to_virt() work as well as kmap() for our
	 * real-world use cases (using 64-bit systems), but we use the latter to
	 * be hyper-correct and account for highmem
	 */
	case FAR_READ:
		if (copy_to_user(addr, kmap(pte_page(pte)) + page_off, len))
			err = -EFAULT;
		kunmap(pte_page(pte));
		break;
	case FAR_WRITE:
		if (copy_from_user(kmap(pte_page(pte)) + page_off, addr, len))
			err = -EFAULT;
		else
			set_page_dirty_lock(pte_page(pte));
		kunmap(pte_page(pte));
		break;
	default:
		err = -EINVAL;
	}

	put_page(pte_page(pte));
	return err ? err : len;
}

int farfetch_init(void)
{
	pr_info("Installing farfetch\n");
	farfetch_ptr = farfetch;
	return 0;
}

void farfetch_exit(void)
{
	pr_info("Removing farfetch\n");
	farfetch_ptr = farfetch_default;
}

module_init(farfetch_init);
module_exit(farfetch_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("farfetch: for fetching pages from afar");
MODULE_AUTHOR("Kent Hall");
