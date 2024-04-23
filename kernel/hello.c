#include "linux/hw_breakpoint.h"
#include "linux/perf_event.h"
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

static inline unsigned long size_inside_page(unsigned long start,
					     unsigned long size)
{
	unsigned long sz;
	sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));
	return min(sz, size);
}

static inline struct task_struct *my_get_task_struct_by_pid(pid_t pid)
{
	struct pid *pid_struct;
	struct task_struct *task;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return NULL;

	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);

	return task;
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
	struct task_struct *task;
	struct mm_struct *mm;
	phys_addr_t pa;
	size_t sz, read = 0;
	void *ptr;
	char *bounce;
	int probe;

	task = my_get_task_struct_by_pid(pid);
	if (!task)
		return 0;

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
	return read;
}

static size_t write_process_memory(pid_t pid, uintptr_t addr, void *buffer,
				   size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	phys_addr_t pa;
	size_t sz, written = 0;
	void *ptr;
	unsigned long copied;

	task = my_get_task_struct_by_pid(pid);
	if (!task)
		return 0;

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
	return written;
}
static size_t read_process_memory2(pid_t pid, uintptr_t addr, void *buffer,
				   size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	phys_addr_t pa;
	size_t sz, read = 0;
	void *ptr;
	char *bounce;
	int probe;

	task = my_get_task_struct_by_pid(pid);
	if (!task)
		return 0;

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
	return read;
}

static size_t write_process_memory2(pid_t pid, uintptr_t addr, void *buffer,
				    size_t size)
{
	struct task_struct *task;
	struct mm_struct *mm;
	phys_addr_t pa;
	size_t sz, written = 0;
	void *ptr;
	unsigned long copied;

	task = my_get_task_struct_by_pid(pid);
	if (!task)
		return 0;

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
	return written;
}

#define MAX_HBP_COUNT 300
#define MAX_INDEX_COUNT 50

#pragma pack(1)
struct My_User_Regs_struct {
	__uint128_t vregs[32];
	u32 fpsr;
	u32 fpcr;

	u64 xregs[31];
	u64 sp;
	u64 pc;
	u64 pstate;

	bool vregs_set[32];
	bool fpsr_set;
	bool fpcr_set;
	bool xregs_set[31];
	bool sp_set;
	bool pc_set;
	bool pstate_set;
};

struct My_HW_struct {
	struct perf_event *hbp[MAX_HBP_COUNT];
	struct My_User_Regs_struct r;
};
#pragma pack()

struct My_HW_struct my_hw_struct[MAX_INDEX_COUNT];

static int current_index = 0;

static void sample_hbp_handler(struct perf_event *bp,
			       struct perf_sample_data *data,
			       struct pt_regs *regs)
{
	int i;
	bool do_vregs_set = false;
	struct My_User_Regs_struct *s;
	struct user_fpsimd_state newstate;
	struct task_struct *target;

	if (bp->attr.sample_regs_user < 0 ||
	    bp->attr.sample_regs_user >= MAX_INDEX_COUNT) {
		pr_info("sample_hbp_handler: invalid index\n");
		return;
	}

	s = &my_hw_struct[bp->attr.sample_regs_user].r;

	for (i = 0; i < 32; i++) {
		if (s->vregs_set[i]) {
			do_vregs_set = true;
			break;
		}
	}
	if (s->fpsr_set) {
		do_vregs_set = true;
	}
	if (s->fpcr_set) {
		do_vregs_set = true;
	}

	if (do_vregs_set) {
		target = current;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
		sve_sync_to_fpsimd(target);
		newstate = target->thread.uw.fpsimd_state;
#else
		newstate = target->thread.fpsimd_state.user_fpsimd;
#endif

		for (i = 0; i < 32; i++) {
			if (s->vregs_set[i]) {
				newstate.vregs[i] = s->vregs[i];
			}
		}
		if (s->fpsr_set) {
			newstate.fpsr = s->fpsr;
		}
		if (s->fpcr_set) {
			newstate.fpcr = s->fpcr;
		}

		target->thread.uw.fpsimd_state = newstate;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 16, 0)
		sve_sync_from_fpsimd_zeropad(target);
#endif
		fpsimd_flush_task_state(target);
	}

	for (i = 0; i < 31; i++) {
		if (s->xregs_set[i]) {
			regs->regs[i] = s->xregs[i];
		}
	}
	if (s->sp_set) {
		regs->sp = s->sp;
	}
	if (s->pstate_set) {
		regs->pstate = s->pstate;
	}
	if (s->pc_set) {
		if (s->pc > 0xFFFFFFFF) {
			regs->pc = s->pc;
		} else {
			regs->pc += s->pc;
		}
	} else {
		regs->pc += 4;
	}
}

static int my_register_breakpoint(struct perf_event **p_sample_hbp, pid_t pid,
				  u64 addr, u64 len, u32 type, u32 given_index)
{
	struct perf_event_attr attr;
	struct task_struct *task;

	task = my_get_task_struct_by_pid(pid);
	if (!task)
		return -1;

	//hw_breakpoint_init(&attr);
	ptrace_breakpoint_init(&attr);

	attr.bp_addr = addr;
	attr.bp_len = len;
	attr.bp_type = type;
	attr.disabled = 0;
	attr.sample_regs_user = given_index;
	*p_sample_hbp = perf_event_create_kernel_counter(
		&attr, -1, task, sample_hbp_handler, NULL);

	put_task_struct(task);

	if (IS_ERR((void __force *)*p_sample_hbp)) {
		int ret = PTR_ERR((void __force *)*p_sample_hbp);
		pr_info(KERN_INFO "register_user_hw_breakpoint failed: %d\n",
			ret);
		*p_sample_hbp = NULL;
		return ret;
	}
	return 0;
}
static int my_register_breakpoint_mult(struct perf_event **p_sample_hbp,
				       pid_t pid, u64 addr, u64 len, u32 type,
				       u32 given_index)
{
	struct task_struct *thread_group = NULL;
	struct task_struct *task;
	struct task_struct *pos;
	int count = 0;
	int tid;

	task = my_get_task_struct_by_pid(pid);
	if (!task)
		return -1;

	thread_group = task->group_leader;
	do {
		if (count >= MAX_HBP_COUNT) {
			break;
		}
		tid = pos->pid;
		my_register_breakpoint(&p_sample_hbp[count], tid, addr, len,
				       type, given_index);
		count++;
	}
	while_each_thread(thread_group, pos);
	return 0;
}
static int my_unregister_breakpoint(struct perf_event *p_sample_hbp)
{
	if (p_sample_hbp) {
		perf_event_release_kernel(p_sample_hbp);
		return 0;
	}
	return -1;
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
	int i, j;
	size_t ret_value;

	switch (cmd) {
	case 1:
	case 2:
	case 3:
	case 4: {
		struct {
			size_t pid;
			uintptr_t addr;
			void *buffer;
			size_t size;
			size_t *ret;
		} args;

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

	} break;
	case 101:
	case 102:
	case 103: {
		struct My_HW_struct *hw_struct;
		struct {
			size_t pid;
			uintptr_t addr;
			u64 len;
			u64 type;
			u64 mode;
			u64 index;
			size_t *ret;
		} hb_args;

		if (copy_from_user(&hb_args, (void *)arg, sizeof(hb_args)))
			return -EFAULT;

		if (cmd == 101) {
			if (current_index >= MAX_INDEX_COUNT ||
			    current_index < 0) {
				current_index = 0;
			}

			hw_struct = &my_hw_struct[current_index];

			memset(hw_struct, 0, sizeof(struct My_HW_struct));

			if (hb_args.mode == 0) {
				ret_value = my_register_breakpoint(
					&my_hw_struct[current_index].hbp[0],
					hb_args.pid, hb_args.addr, hb_args.len,
					hb_args.type, current_index);

			} else {
				ret_value = my_register_breakpoint_mult(
					&my_hw_struct[current_index].hbp[0],
					hb_args.pid, hb_args.addr, hb_args.len,
					hb_args.type, current_index);
			}
			if (ret_value == 0) {
				ret_value = current_index;
				current_index++;
			}
		} else if (cmd == 102) {
			for (i = 0; i < MAX_HBP_COUNT; i++) {
				if (my_hw_struct[hb_args.index].hbp[i]) {
					my_unregister_breakpoint(
						my_hw_struct[current_index]
							.hbp[i]);
				}
			}
			memset(&my_hw_struct[hb_args.index], 0,
			       sizeof(struct My_HW_struct));
			ret_value = 0;
		} else if (cmd == 103) {
			for (i = 0; i < MAX_INDEX_COUNT; i++) {
				for (j = 0; j < MAX_HBP_COUNT; j++) {
					if (my_hw_struct[i].hbp[j]) {
						my_unregister_breakpoint(
							my_hw_struct[i].hbp[j]);
					}
				}
			}
			memset(my_hw_struct, 0, sizeof(my_hw_struct));
		}

		if (copy_to_user(hb_args.ret, &ret_value, sizeof(ret_value)))
			return -EFAULT;
	} break;

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
