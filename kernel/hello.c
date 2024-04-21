#include "linux/pid.h"
#include "linux/sched/task.h"
#include "linux/types.h"
#include <linux/cred.h>
#include <linux/stddef.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/current.h>
#include <asm/cpu.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#define DEVICE_NAME "kernel_hack"

//extern struct mm_struct *get_task_mm(struct task_struct *task);

static inline unsigned long size_inside_page(unsigned long start,
					     unsigned long size)
{
	unsigned long sz;
	sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));
	return min(sz, size);
}

static phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
	p4d_t *p4d;
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;

	phys_addr_t page_addr;
	uintptr_t page_offset;

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		return 0;
	}
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d)) {
		return 0;
	}
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud)) {
		return 0;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd)) {
		return 0;
	}
	pte = pte_offset_kernel(pmd, va);
	if (pte_none(*pte)) {
		return 0;
	}
	if (!pte_present(*pte)) {
		return 0;
	}
	//页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	//页内偏移
	page_offset = va & (PAGE_SIZE - 1);
	return page_addr + page_offset;
}

static size_t read_process_memory(pid_t pid, uintptr_t addr, void *buffer,
				  size_t size)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct mm_struct *mm;
	phys_addr_t pa;
	size_t sz, read = 0;
	void *ptr;
	char *bounce;
	int probe;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return 0;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		goto put_pid;

	mm = get_task_mm(task);
	if (!mm || IS_ERR(mm))
		goto put_task_struct;

	bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bounce)
		goto mmput;

	while (size > 0) {
		sz = size_inside_page(addr, size);

		pa = translate_linear_address(mm, addr);
		if (!pa)
			goto cc;

		if (!pfn_valid(__phys_to_pfn(pa)))
			goto cc;

		ptr = ioremap_cache(pa, sz);
		if (!ptr)
			goto cc;

		probe = copy_from_kernel_nofault(bounce, ptr, sz);
		iounmap(ptr);
		if (probe)
			goto cc;

		if (copy_to_user(buffer, bounce, sz))
			goto cc;

		read += sz;
	cc:
		size -= sz;
		addr += sz;
		buffer += sz;
		/* if (should_stop_iteration())
			break; */
	}
	kfree(bounce);
mmput:
	mmput(mm);
put_task_struct:
	put_task_struct(task);
put_pid:
	put_pid(pid_struct);
	return read;
}

static size_t write_process_memory(pid_t pid, uintptr_t addr, void *buffer,
				   size_t size)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct mm_struct *mm;
	phys_addr_t pa;
	size_t sz, written = 0;
	void *ptr;
	unsigned long copied;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return 0;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		goto put_pid;

	mm = get_task_mm(task);
	if (!mm || IS_ERR(mm))
		goto put_task_struct;

	while (size > 0) {
		sz = size_inside_page(addr, size);

		pa = translate_linear_address(mm, addr);
		if (!pa)
			goto cc;

		if (!pfn_valid(__phys_to_pfn(pa)))
			goto cc;

		ptr = ioremap_cache(pa, sz);
		if (!ptr)
			goto cc;

		copied = copy_from_user(ptr, buffer, sz);
		iounmap(ptr);
		if (copied)
			goto cc;

		written += sz;
	cc:
		size -= sz;
		addr += sz;
		buffer += sz;
		/* if (should_stop_iteration())
			break; */
	}
	mmput(mm);
put_task_struct:
	put_task_struct(task);
put_pid:
	put_pid(pid_struct);
	return written;
}
static size_t read_process_memory2(pid_t pid, uintptr_t addr, void *buffer,
				   size_t size)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct mm_struct *mm;
	phys_addr_t pa;
	size_t sz, read = 0;
	void *ptr;
	char *bounce;
	int probe;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return 0;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		goto put_pid;

	mm = get_task_mm(task);
	if (!mm || IS_ERR(mm))
		goto put_task_struct;

	bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bounce)
		goto mmput;

	while (size > 0) {
		sz = size_inside_page(addr, size);

		pa = translate_linear_address(mm, addr);
		if (!pa)
			goto cc;

		ptr = xlate_dev_mem_ptr(pa);
		if (!ptr)
			goto cc;

		probe = copy_from_kernel_nofault(bounce, ptr, sz);
		unxlate_dev_mem_ptr(pa, ptr);
		if (probe)
			goto cc;

		if (copy_to_user(buffer, bounce, sz))
			goto cc;

		read += sz;
	cc:
		size -= sz;
		addr += sz;
		buffer += sz;
		/* if (should_stop_iteration())
			break; */
	}
	kfree(bounce);
mmput:
	mmput(mm);
put_task_struct:
	put_task_struct(task);
put_pid:
	put_pid(pid_struct);
	return read;
}

static size_t write_process_memory2(pid_t pid, uintptr_t addr, void *buffer,
				    size_t size)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct mm_struct *mm;
	phys_addr_t pa;
	size_t sz, written = 0;
	void *ptr;
	unsigned long copied;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return 0;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		goto put_pid;

	mm = get_task_mm(task);
	if (!mm || IS_ERR(mm))
		goto put_task_struct;

	while (size > 0) {
		sz = size_inside_page(addr, size);

		pa = translate_linear_address(mm, addr);
		if (!pa)
			goto cc;

		ptr = xlate_dev_mem_ptr(pa);
		if (!ptr)
			goto cc;

		copied = copy_from_user(ptr, buffer, sz);
		unxlate_dev_mem_ptr(pa, ptr);
		if (copied)
			goto cc;

		written += sz;
	cc:
		size -= sz;
		addr += sz;
		buffer += sz;
		/* if (should_stop_iteration())
			break; */
	}
	mmput(mm);
put_task_struct:
	put_task_struct(task);
put_pid:
	put_pid(pid_struct);
	return written;
}
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
	struct memory_args {
		pid_t pid;
		uintptr_t addr;
		void *buffer;
		size_t size;
		size_t *ret;
	} args;
	size_t ret_value;

	switch (cmd) {
	case 1:
	case 2:
	case 3:
	case 4:
		if (copy_from_user(&args, (void *)arg, sizeof(args)))
			return -EFAULT;

		if (cmd == 1)
			ret_value = read_process_memory(args.pid, args.addr,
							args.buffer, args.size);
		else if (cmd == 2)
			ret_value = write_process_memory(
				args.pid, args.addr, args.buffer, args.size);
		else if (cmd == 3)
			ret_value = read_process_memory2(
				args.pid, args.addr, args.buffer, args.size);
		else if (cmd == 4)
			ret_value = write_process_memory2(
				args.pid, args.addr, args.buffer, args.size);
		if (copy_to_user(args.ret, &ret_value, sizeof(ret_value)))
			return -EFAULT;
		
		break;
	default:
		return -EINVAL;
	}
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
