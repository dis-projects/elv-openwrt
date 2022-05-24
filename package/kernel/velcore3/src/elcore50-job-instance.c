// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020-2021 RnD Center "ELVEES", JSC
 */

#include <linux/anon_inodes.h>
#include <linux/hash.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/uaccess.h>

#include "elcore50-debug.h"
#include "elcore50-job-instance.h"
#include "elcore50-mmu.h"
#include "elcore50-syscall.h"

#define E50_CACHE_L1	BIT(0)
#define E50_CACHE_L2	BIT(1)

static int elcore50_parse_args(struct elcore50_job_inst_desc *desc,
			       struct elcore50_job_instance *inst,
			       int argc)
{
	struct elcore50_core *core = desc->core;
	struct elcore50_job_arg *earg;
	char *stack_cur = desc->stack_args;
	int reg = 0, i, j, ret, larg = 0;
	uint32_t local_addr;
	int buf_fd;
	struct fd fd;

	if (argc) {
		desc->args = kcalloc(argc, sizeof(struct userptr_mapper *),
				     GFP_KERNEL);
		if (!desc->args)
			return -ENOMEM;

		desc->arg_files = kcalloc(argc, sizeof(struct file *),
					  GFP_KERNEL);
		if (!desc->arg_files) {
			kfree(desc->args);
			return -ENOMEM;
		}
	}

	for (i = 0, j = 0; i < inst->argc; i++) {
		void *basic_dest;

		earg = &inst->args[i];
		switch (earg->type) {
		case ELCORE50_TYPE_BASIC:
			if (reg < E50_ARG_REGS && earg->basic.size <= 0x8) {
				basic_dest = &desc->arg_regs[reg];
				reg++;
			} else {
				basic_dest = stack_cur;
				stack_cur += round_up(earg->basic.size, 0x8);
			}
			ret = copy_from_user(basic_dest,
					     (void __user *) earg->basic.p,
					     earg->basic.size);
			if (ret != 0) {
				dev_err(core->dev,
					"could not copy buffer, remaining: %x\n",
					ret);
				ret = -EFAULT;
				goto free_args;
			}
			break;
		case ELCORE50_TYPE_NC_GLOBAL_MEMORY:
		case ELCORE50_TYPE_GLOBAL_MEMORY:
		case ELCORE50_TYPE_DMA_MEMORY:
			if (earg->type == ELCORE50_TYPE_DMA_MEMORY)
				buf_fd = earg->dma_memory.mapper_fd;
			else
				buf_fd = earg->global_memory.mapper_fd;

			fd = fdget(buf_fd);
			if (!fd.file ||
				fd.file->f_op != &elcore50_mapper_ops) {
				ret = -EINVAL;
				goto free_args;
			}

			desc->args[j] =
				kzalloc(sizeof(struct elcore50_buf_desc),
					GFP_KERNEL);
			if (!desc->args[j]) {
				ret = -ENOMEM;
				goto free_args;
			}
			desc->arg_files[j] = get_file(fd.file);
			desc->args[j]->mapper = fd.file->private_data;
			desc->args[j]->type = earg->type;
			fdput(fd);

			/*
			 * Since the MMU is not yet initialized, and therefore
			 * the virtual addresses are unknown, this pointer is
			 * set up to be written once the MMU is filled.
			 */
			if (reg < E50_ARG_REGS) {
				desc->args[j]->wr_addr = (uint64_t *)
							&desc->arg_regs[reg];
				reg++;
			} else {
				desc->args[j]->wr_addr = (uint64_t *)stack_cur;
				stack_cur += 0x8;
			}
			desc->args[j]->arg_type = earg->type;
			j++;
			break;
		case ELCORE50_TYPE_LOCAL_MEMORY:
			local_addr = desc->local_args_addr[larg];
			if (reg < E50_ARG_REGS) {
				desc->arg_regs[reg] = local_addr;
				reg++;
			} else {
				*(uint32_t *)stack_cur = local_addr;
				stack_cur += 0x8;
			}
			larg++;
			break;
		}
	}
	return 0;
free_args:
	if (argc) {
		for (i = 0; i < desc->argc; ++i) {
			if (desc->arg_files[i])
				fput(desc->arg_files[i]);
		}
		kfree(desc->arg_files);
		for (i = 0; i < desc->argc; ++i)
			kfree(desc->args[i]);
		kfree(desc->args);
	}
	return ret;
}

struct elcore50_job_arg_sort {
	struct elcore50_job_arg arg;
	int origin_index;
};

static int local_mem_compare(const void *a, const void *b)
{
	const struct elcore50_job_arg_sort *arg1 = a, *arg2 = b;

	return arg1->arg.local_memory.size - arg2->arg.local_memory.size;
}

static int find_args_by_closest_total_size(struct elcore50_job_arg_sort *args,
					   const int argc,
					   const int contiguous_memsize,
					   int *are_args_in_lowbank)
{
	int curr_sum, max_sum = 0, start = 0, i = 0;
	int *are_args_in_lowbank_tmp;

	are_args_in_lowbank_tmp = kcalloc(argc, sizeof(int), GFP_KERNEL);
	if (!are_args_in_lowbank_tmp)
		return -ENOMEM;

	curr_sum = args[0].arg.local_memory.size;

	// To find max_sum less than contiguous_memsize
	for (i = 1; i < argc; i++) {

		// Update max_sum if it becomes greater than curr_sum
		if (max_sum < curr_sum && curr_sum <= contiguous_memsize) {
			max_sum = curr_sum;
			memcpy(are_args_in_lowbank, are_args_in_lowbank_tmp,
			       sizeof(int) * argc);
		}

		// If curr_sum becomes greater than
		// contiguous_memsize subtract starting elements of array
		while (curr_sum + args[i].arg.local_memory.size >
				contiguous_memsize && start < i) {
			curr_sum -= args[start].arg.local_memory.size;
			// Clear index of this element from bit array
			are_args_in_lowbank_tmp[args[start].origin_index] = 0;
			start++;
		}

		// Add elements to curr_sum
		curr_sum += args[i].arg.local_memory.size;
		// Set index of this element to bit array
		are_args_in_lowbank_tmp[args[i].origin_index] = 1;
	}

	//Adding an extra check for last subarray
	if (max_sum < curr_sum && curr_sum <= contiguous_memsize) {
		max_sum = curr_sum;
		memcpy(are_args_in_lowbank, are_args_in_lowbank_tmp,
		       sizeof(int) * argc);
	}

	kfree(are_args_in_lowbank_tmp);
	return max_sum;
}

static int try_arrange_local_args(struct elcore50_job_inst_desc *desc,
				  struct elcore50_job_instance *inst,
				  int largc, uint32_t args_size,
				  uint32_t localmem_required,
				  struct elcore50_job_arg_sort *sort_earg)
{
	uint32_t localmem = PHYS_INTERNAL_INTERLEAVE_DSP;
	uint32_t localmem_high = PHYS_INTERNAL_INTERLEAVE_DSP + 0x40000;
	int i, ret, *are_args_in_lowbank = NULL;

	if (localmem_required == SZ_512K) {
		for (i = 0, largc = 0; i < inst->argc; ++i) {
			if (inst->args[i].type != ELCORE50_TYPE_LOCAL_MEMORY)
				continue;
			desc->local_args_addr[largc] = localmem;
			localmem += inst->args[i].local_memory.size;
			largc++;
		}
		return 0;
	}

	are_args_in_lowbank = kcalloc(largc, sizeof(int), GFP_KERNEL);
	if (!are_args_in_lowbank)
		return -ENOMEM;

	ret = find_args_by_closest_total_size(sort_earg, largc,
					      localmem_required / 2,
					      are_args_in_lowbank);
	if (ret < 0) {
		kfree(are_args_in_lowbank);
		return ret;
	}

	args_size = args_size - ret;
	if ((ret > localmem_required / 2) ||
			(args_size  > localmem_required / 2)) {
		kfree(are_args_in_lowbank);
		return -EINVAL;
	}

	for (i = 0, largc = 0; i < inst->argc; ++i) {
		if (inst->args[i].type != ELCORE50_TYPE_LOCAL_MEMORY)
			continue;
		if (are_args_in_lowbank[largc]) {
			desc->local_args_addr[largc] = localmem;
			localmem += inst->args[i].local_memory.size;
		} else {
			desc->local_args_addr[largc] = localmem_high;
			localmem_high += inst->args[i].local_memory.size;
		}
		largc++;
	}

	kfree(are_args_in_lowbank);
	return 0;
}

static int arrange_local_args(struct elcore50_job_inst_desc *desc,
			      struct elcore50_job_instance *inst,
			      int largc, uint32_t localmem_arg_size,
			      uint32_t localmem_required)
{
	int i, ret;
	struct elcore50_job_arg_sort *sort_earg;

	// create copy of job local args for sorting
	sort_earg = kcalloc(largc, sizeof(struct elcore50_job_arg_sort),
			     GFP_KERNEL);
	if (!sort_earg)
		return -ENOMEM;

	for (i = 0, largc = 0; i < inst->argc; ++i) {
		if (inst->args[i].type != ELCORE50_TYPE_LOCAL_MEMORY)
			continue;
		memcpy(&sort_earg[largc].arg, &inst->args[i],
		       sizeof(struct elcore50_job_arg));
		sort_earg[largc].origin_index = largc;
		largc++;
	}

	/* sort ascending arg size */
	sort(sort_earg, largc, sizeof(struct elcore50_job_arg_sort),
	     &local_mem_compare, NULL);

	do {
		ret = try_arrange_local_args(desc, inst, largc,
					     localmem_arg_size,
					     localmem_required, sort_earg);
		if (ret == -ENOMEM)
			break;
		if (ret) {
			localmem_required += SZ_128K;
			desc->l2_size--;
		}
	} while (ret);

	kfree(sort_earg);
	return ret;
}

static int elcore50_job_inst_release(struct inode *inode, struct file *file)
{
	int i;
	struct elcore50_job_inst_desc *desc = file->private_data;

	elcore50_cancel_job_inst(desc);
	for (i = 0; i < desc->argc; ++i)
		fput(desc->arg_files[i]);
	fput(desc->job_file);
	if (desc->dma_pool)
		mmu_pool_destroy(desc->dma_pool);
	kfree(desc->arg_files);
	kfree(desc->local_args_addr);
	for (i = 0; i < desc->argc; ++i)
		kfree(desc->args[i]);
	kfree(desc->args);
	kfree(desc->stack_args);
	kfree(desc);
	return 0;
}

static unsigned int elcore50_job_inst_poll(struct file *file, poll_table *wait)
{
	struct elcore50_job_inst_desc *desc = file->private_data;

	poll_wait(file, &desc->poll_waitq, wait);
	/* The spec doesn't suggest which events the job waits for, so
	 * we'll signal every IO event */
	if (desc->state > ELCORE50_JOB_STATUS_SYSCALL)
		return POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;

	// Send event if syscall data is ready
	if ((desc->state == ELCORE50_JOB_STATUS_SYSCALL) &&
	     (desc->message.type == ELCORE50_MESSAGE_SYSCALL))
		return POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;
	return 0;
}

static ssize_t elcore50_job_inst_read(struct file *file, char __user *buf,
				      size_t size, loff_t *ppos)
{
	struct elcore50_job_inst_desc *desc =
		(struct elcore50_job_inst_desc *)file->private_data;

	WARN_ON(size != sizeof(struct elcore50_message));

	if (desc->state != ELCORE50_JOB_STATUS_SYSCALL)
		return -EINVAL;

	return sizeof(struct elcore50_message) -
			copy_to_user(buf, &desc->message,
				     sizeof(struct elcore50_message));
}

static ssize_t elcore50_job_inst_write(struct file *file,
				       const char __user *buf, size_t size,
				       loff_t *ppos)
{
	struct elcore50_job_inst_desc *desc =
		(struct elcore50_job_inst_desc *)file->private_data;
	struct elcore50_message message;
	ssize_t ret;

	if (desc->state != ELCORE50_JOB_STATUS_SYSCALL)
		return -EINVAL;

	WARN_ON(size != sizeof(struct elcore50_message));

	ret = copy_from_user(&message, buf, sizeof(struct elcore50_message));
	if (ret)
		return ret;

	if (message.type == ELCORE50_MESSAGE_SYSCALL_REPLY) {
		desc->syscall_handled = 1;
		memcpy(&desc->message, &message,
		       sizeof(struct elcore50_message));
		wake_up(&desc->syscall_waitq);
	} else
		WARN_ON(1);

	return sizeof(struct elcore50_message);
}

static const struct file_operations elcore50_job_inst_fops = {
	.release = elcore50_job_inst_release,
	.poll = elcore50_job_inst_poll,
	.read = elcore50_job_inst_read,
	.write = elcore50_job_inst_write
};

int elcore50_enqueue_job_inst(struct elcore50_core *core, void __user *arg)
{
	struct elcore50_job_inst_desc *desc;
	struct elcore50_job_arg *earg;
	struct elcore50_job_instance *inst;
	struct elcore50_job_inst_dbg_desc *dbg_desc;
	int ret, i, free_regs, argc = 0, largc = 0;
	size_t stack_args, local_mem, localmem_required, dma_mem, nc_mem;
	unsigned long flags;
	struct fd fd;

	free_regs = E50_ARG_REGS;
	stack_args = 0;
	local_mem = 0;
	largc = 0;
	nc_mem = 0;
	dma_mem = 0;

	desc = kzalloc(sizeof(struct elcore50_job_inst_desc), GFP_KERNEL);
	inst = kzalloc(sizeof(struct elcore50_job_instance), GFP_KERNEL);
	if (!desc || !inst)
		return -ENOMEM;

	ret = copy_from_user(inst, arg, sizeof(struct elcore50_job_instance));
	if (ret) {
		ret = -EACCES;
		goto clean_kfree;
	}
	fd = fdget(inst->job_fd);
	if (!fd.file || fd.file->f_op != &elcore50_job_fops) {
		ret = -EBADFD;
		WARN_ON(1);
		goto job_fdput;
	}
	desc->job_file = get_file(fd.file);
	desc->job_desc = fd.file->private_data;
	desc->dsp_pool = desc->job_desc->dsp_pool;
	desc->core = core;
	fdput(fd);

	desc->pid = task_pid_nr(current);
	strcpy(desc->name, inst->name);

	spin_lock_init(&desc->state_lock);
	mutex_init(&desc->debug_lock);

	for (i = 0; i < inst->argc; i++) {
		earg = &inst->args[i];
		switch (earg->type) {
		case ELCORE50_TYPE_BASIC:
			if (free_regs > 0  && earg->basic.size <= 0x8)
				free_regs--;
			else
				stack_args += round_up(earg->basic.size, 8);
			break;
		case ELCORE50_TYPE_DMA_MEMORY:
		case ELCORE50_TYPE_GLOBAL_MEMORY:
		case ELCORE50_TYPE_NC_GLOBAL_MEMORY:
			argc++;
			if (free_regs > 0)
				free_regs--;
			else
				stack_args += 8;
			break;
		case ELCORE50_TYPE_LOCAL_MEMORY:
			local_mem += earg->local_memory.size;
			if (free_regs > 0)
				free_regs--;
			else
				stack_args += 8;
			largc++;
			break;
		}
	}

	/* Local args cannot be used in conjunction with XYRAM sections */
	if (local_mem && desc->job_desc->xyram) {
		dev_err(core->dev,
			"Local memory cannot be used in conjunction with XYRAM sections\n");
		ret = -ENOMEM;
		goto job_fdput;
	}

	/* TODO: users should be able to specify stack size */
	if (local_mem == 0) {
		desc->l2_size = L2_CACHE_512;
		localmem_required = 0;
	} else if (local_mem <= SZ_512K - SZ_256K) {
		desc->l2_size = L2_CACHE_256;
		localmem_required = SZ_256K;
	} else if (local_mem <= SZ_512K - SZ_128K) {
		desc->l2_size = L2_CACHE_128;
		localmem_required = SZ_512K - SZ_128K;
	} else if (local_mem <= SZ_512K) {
		desc->l2_size = L2_CACHE_NONE;
		localmem_required = SZ_512K;
	} else {
		dev_err(core->dev, "Not enough local memory for this job\n");
		ret = -ENOMEM;
		goto job_fdput;
	}

	desc->stack_start = desc->job_desc->stack->mapper->size - stack_args;
	desc->stack_args_size = stack_args;
	desc->argc = argc;

	if (stack_args > desc->job_desc->stack->mapper->size) {
		dev_err(core->dev, "Stack overflow: too many arguments\n");
		ret = -ENOMEM;
		goto job_fdput;
	}

	if (desc->stack_args_size) {
		desc->stack_args = kzalloc(desc->stack_args_size, GFP_KERNEL);
		if (!desc->stack_args) {
			ret = -ENOMEM;
			goto job_fdput;
		}
	}

	if (largc) {
		desc->local_args_addr = kcalloc(largc, sizeof(uint32_t),
						GFP_KERNEL);
		if (!desc->local_args_addr)
			goto clean_stackargs;

		ret = arrange_local_args(desc, inst, largc, local_mem,
					 localmem_required);
		if (ret)
			goto clean_local_args;
	}

	ret = elcore50_parse_args(desc, inst, argc);
	if (ret) {
		dev_err(core->dev, "Failed to parse arguments\n");
		goto clean_local_args;
	}

	for (i = 0; i < desc->argc; i++) {
		if (desc->args[i]->arg_type == ELCORE50_TYPE_DMA_MEMORY)
			dma_mem += desc->args[i]->mapper->size_aligned;
		else if (desc->args[i]->arg_type ==
				ELCORE50_TYPE_NC_GLOBAL_MEMORY)
			nc_mem += desc->args[i]->mapper->size_aligned;
	}

	if (nc_mem) {
		i = 31 - (nc_mem - 1) / (128 * SZ_1M);
		desc->noncached_regions = GENMASK(31, i);
		desc->nc_mem_current = (1UL << 32) - round_up(nc_mem, SZ_128M);
	}

	desc->launcher_vaddr = inst->launcher_virtual_address;
	desc->entry_point_vaddr = inst->entry_point_virtual_address;

	init_waitqueue_head(&desc->poll_waitq);
	init_waitqueue_head(&desc->poll_dbg_waitq);
	init_waitqueue_head(&desc->irq_waitq);
	init_waitqueue_head(&desc->syscall_waitq);
	init_waitqueue_head(&desc->debug_waitq);

	if (dma_mem) {
		desc->dma_pool = mmu_pool_create(ilog2(E50_PAGE_SIZE), -1);
		if (IS_ERR(desc->dma_pool)) {
			ret = PTR_ERR(desc->dma_pool);
			goto clean_args;
		}

		ret = mmu_pool_add(desc->dma_pool, (1ULL << 32), dma_mem, -1);
		if (ret)
			goto clean_dmapool;
	}

	ret = anon_inode_getfd("elcorejobinstance",
			       &elcore50_job_inst_fops, desc, O_RDWR);
	if (ret < 0)
		goto clean_dmapool;
	desc->self_fd = inst->job_instance_fd = ret;

	if (inst->debug_enable) {
		dbg_desc = kzalloc(sizeof(struct elcore50_job_inst_dbg_desc),
				   GFP_KERNEL);
		desc->debug_state = ELCORE50_DBG_INTERRUPTED;
		desc->stop_reason = ELCORE50_STOP_REASON_DBG_INTERRUPT;
		desc->attached = 1;
		ret = export_dbg_fd(dbg_desc);
		if (ret < 0) {
			kfree(dbg_desc);
			goto clean_fd;
		}
		inst->debug_fd = ret;
		dbg_desc->inst = desc;
		fd = fdget(desc->self_fd);
		dbg_desc->inst_file = get_file(fd.file);
		fdput(fd);
	}

	ret = copy_to_user(arg, inst, sizeof(struct elcore50_job_instance));
	if (ret) {
		ret = -EACCES;
		goto clean_debug_fd;
	}

	INIT_WORK(&desc->worker, elcore50_job_inst_run);
	spin_lock_irqsave(&core->queue_lock, flags);
	list_add_tail(&desc->queue_node, &core->job_queue);
	queue_work(core->work_q, &desc->worker);
	spin_unlock_irqrestore(&core->queue_lock, flags);
	kfree(inst);
	return 0;
clean_debug_fd:
	if (inst->debug_enable) {
		put_unused_fd(inst->debug_fd);
		kfree(dbg_desc);
	}
clean_fd:
	put_unused_fd(inst->job_instance_fd);
clean_dmapool:
	if (desc->dma_pool)
		mmu_pool_destroy(desc->dma_pool);
clean_args:
	for (i = 0; i < desc->argc; ++i)
		fput(desc->arg_files[i]);
	kfree(desc->arg_files);
	for (i = 0; i < desc->argc; ++i)
		kfree(desc->args[i]);
	kfree(desc->args);
clean_local_args:
	kfree(desc->local_args_addr);
clean_stackargs:
	kfree(desc->stack_args);
job_fdput:
	fput(desc->job_file);
clean_kfree:
	kfree(desc);
	kfree(inst);
	dev_err(core->dev, "queueing failed %d\n", ret);
	return ret;
}

int elcore50_cancel_job_inst(struct elcore50_job_inst_desc *desc)
{
	unsigned long flags;

	desc->abort = 1;
#ifndef ELCORE50_NO_IRQS
	wake_up(&desc->irq_waitq);
#endif
	wake_up(&desc->syscall_waitq);
	if (cancel_work_sync(&desc->worker)) {
		spin_lock_irqsave(&desc->core->queue_lock, flags);
		list_del(&desc->queue_node);
		spin_unlock_irqrestore(&desc->core->queue_lock, flags);
		desc->debug_result = -EINVAL;
			desc->debug_state = ELCORE50_DBG_EXITED;
		wake_up(&desc->debug_waitq);
	}

	return 0;
}

static void get_job_inst_results(struct elcore50_job_inst_desc *desc)
{
	uint32_t irq_status;
	unsigned long flags;
	struct elcore50_core *core = desc->core;

	irq_status = elcore50_read(core, DSP_DQSTR);

	spin_lock_irqsave(&desc->state_lock, flags);
	if (irq_status & DQSTR_ERRS) {
		desc->error = ELCORE50_JOB_STATUS_ERROR;
		dev_warn(core->dev, "Job failed with DQSTR: %x", irq_status);
		print_dump(core);
	} else if ((irq_status & DQSTR_STP) == DQSTR_STP)
		desc->error = ELCORE50_JOB_STATUS_SUCCESS;
	else {
		print_dump(core);
		WARN_ON(1);
	}
	spin_unlock_irqrestore(&desc->state_lock, flags);
}

static unsigned int get_cache_prefetch_boundary(void)
{
	/* TODO: Fix for different pages */
	return L1_CTRL_PFB_4K;
}

static void caches_setup(struct elcore50_job_inst_desc *desc)
{
	uint32_t reg_tmp;
	struct elcore50_core *core = desc->core;

	/* L0 setup */
	elcore50_write(L0DC_CTRL_L0En | L0DC_CTRL_L0CNTREn, core, L0DC_CTRL);
	reg_tmp = CTRL_ASIDINV | CTRL_PRAMEn | CTRL_XYEn | CTRL_EPortEn |
			CTRL_ST_PRED | CTRL_PF | CTRL_PFN(1) | CTRL_DOPF |
			CTRL_DOPFN(2) |
			CTRL_PFB(get_cache_prefetch_boundary()) |
			CTRL_VW_RM | CTRL_VR_DM | CTRL_SVISync | CTRL_SVBSync |
			CTRL_BrCtrlEn | CTRL_MBAR | CTRL_AddrCheck |
			CTRL_EPROTSP(2);
	elcore50_write(reg_tmp, core, DSP_CTRL);

	/* L1 setup */
	if (mod_caches & E50_CACHE_L1) {
		reg_tmp = L1DC_CTRL_EN | L1DC_CTRL_CEN | L1DC_CTRL_WRBK |
				L1DC_CTRL_WRAL | L1DC_CTRL_INVL2 |
				L1DC_CTRL_REFILL(4) |
				L1DC_CTRL_PFSN(L1DC_CTRL_PFN_8) |
				L1DC_CTRL_PFVN(L1DC_CTRL_PFN_8) |
				L1DC_CTRL_PFIN(L1DC_CTRL_PFN_1) |
				L1DC_CTRL_PFB(get_cache_prefetch_boundary()) |
				L1DC_CTRL_PFBWEN;
		elcore50_write(reg_tmp, core, L1DC_CTRL);

		reg_tmp = L1IC_CTRL_EN | L1IC_CTRL_PF | L1IC_CTRL_L1PFN(3) |
				L1IC_CTRL_PFB(get_cache_prefetch_boundary()) |
				L1IC_CTRL_CEN;
		elcore50_write(reg_tmp, core, L1IC_CTRL);
	} else {
		reg_tmp = elcore50_read(core, L1DC_CTRL);
		elcore50_write(reg_tmp & ~L1DC_CTRL_EN, core, L1DC_CTRL);
		reg_tmp = elcore50_read(core, L1IC_CTRL);
		elcore50_write(reg_tmp & ~L1IC_CTRL_EN, core, L1IC_CTRL);
	}

	/* L2 setup */
	if (mod_caches & E50_CACHE_L2 && !desc->job_desc->xyram) {
		reg_tmp = desc->l2_size << L2_CTRL_CV_OFFT;
		elcore50_write(reg_tmp | L2_CTRL_EN | L2_CTRL_CountersEN |
			       L2_CTRL_WR(2) | L2_CTRL_UCAXICACHE(0xf) |
			       L2_CTRL_AXIPROT(2),
			       core, L2_CTRL);
	} else {
		reg_tmp = elcore50_read(core, L2_CTRL) |
			L2_CTRL_UCAXICACHE(0xf) | L2_CTRL_AXIPROT(2);
		elcore50_write(reg_tmp & ~L2_CTRL_EN, core, L2_CTRL);
	}
}

static void caches_inval(struct elcore50_job_inst_desc *desc)
{
	uint32_t reg_tmp;
	int ret;
	struct elcore50_core *core = desc->core;

	elcore50_write(DSP_INCTRL_INVAL_ALL, core, DSP_INVCTRL);
	ret = elcore50_pollreg_timeout(core, DSP_MBARREG, reg_tmp,
				       reg_tmp == 0,
				       0, E50_CACHE_TIMEOUT_USEC);
	WARN_ON(ret);
}

static void caches_flush_after_run(struct elcore50_job_inst_desc *desc)
{
	uint32_t i, reg_tmp;
	struct elcore50_core *core = desc->core;

	/* Stop prefetchers */
	reg_tmp = elcore50_read(core, DSP_CTRL);
	reg_tmp &= ~(CTRL_PF | CTRL_DOPF);
	elcore50_write(reg_tmp, core, DSP_CTRL);

	if (mod_caches & E50_CACHE_L1) {
		reg_tmp = elcore50_read(core, L1DC_CTRL);
		reg_tmp &= ~L1DC_CTRL_PREFETCHERS;
		elcore50_write(reg_tmp, core, L1DC_CTRL);

		reg_tmp = elcore50_read(core, L1IC_CTRL);
		reg_tmp &= ~L1IC_CTRL_PF;
		elcore50_write(reg_tmp, core, L1IC_CTRL);
	}

	elcore50_write(DSP_INVCTRL_FLUSH_ALL, core, DSP_INVCTRL);
	while (elcore50_read(core, DSP_MBARREG) != 0) {
		for (i = 0; i < VMMU_TLBS; ++i) {
			reg_tmp = elcore50_read(core, VMMU_TLB_CTRL +
							i * sizeof(u32));
			reg_tmp |= VMMU_TLB_CTRL_DUMMY;
			elcore50_write(reg_tmp, core, VMMU_TLB_CTRL +
						i * sizeof(u32));
		}
	}
}

static void elcore50_write_regs(struct elcore50_job_inst_desc *desc)
{
	struct elcore50_core *core = desc->core;
	struct cluster_priv *drv_priv = core->drv_priv;
	struct elcore50_buf_desc *stack = desc->job_desc->stack;
	struct elcore50_job_desc *job_desc = desc->job_desc;
	int i;
	uint32_t stack_wr = stack->vaddr_mmu_dsp + desc->stack_start;

	for (i = 0; i < E50_ARG_REGS; i++)
		elcore50_buf_cpy(drv_priv, i * 0x8 + DSP_R0 + core->dsp_regs,
				 &desc->arg_regs[i], 0x8);
	elcore50_write(stack_wr, core, DSP_R12);
	elcore50_write(stack_wr, core, DSP_R13);
	if (desc->launcher_vaddr)
		elcore50_write(desc->launcher_vaddr, core, DSP_PC);
	memcpy(stack->mapper->vaddr + desc->stack_start, desc->stack_args,
	       desc->stack_args_size);
	if (desc->stack_args_size)
		sync_buffer(core, desc->stack_args_size, desc->stack_start,
			    stack->mapper, ELCORE50_BUF_SYNC_DIR_TO_DEVICE);
	elcore50_write(desc->entry_point_vaddr, core,
			desc->launcher_vaddr ? DSP_R8 : DSP_PC);
	elcore50_write(desc->entry_point_vaddr, core, DSP_ERTAR);
	elcore50_write(desc->entry_point_vaddr, core, DSP_DRTAR);
	elcore50_write(desc->entry_point_vaddr, core, DSP_IRTAR);
	elcore50_write((u32)job_desc->pt4_dma_addr, core, VMMU_PTW_PBA_L);
	elcore50_write((u32)(job_desc->pt4_dma_addr >> 32), core,
		       VMMU_PTW_PBA_H);
// VP behaves differently, rf#12206
#ifdef ELCORE50_VP
	elcore50_write(VMMU_PTW_CFG_41B, core, VMMU_PTW_CFG);
#else
	elcore50_write(VMMU_PTW_CFG_41B | VMMU_PTW_CFG_INV |
		       VMMU_PTW_CFG_A_CACHE(0xf) | VMMU_PTW_CFG_A_PROT(2) |
		       VMMU_PTW_CFG_PREFETCH, core, VMMU_PTW_CFG);
#endif
	for (i = 0; i < VMMU_TLBS; i++)
		elcore50_write(0, core, VMMU_TLB_CTRL + i * sizeof(u32));
	elcore50_write(0xFFFFFFFF, core, DSP_MREGIONS);
	elcore50_write(0xFFFFFFFF & ~desc->noncached_regions, core,
		       DSP_CREGIONS);
	elcore50_write(0, core, DSP_IMASKR);
}

static void elcore50_core_run(struct elcore50_job_inst_desc *desc)
{
	struct elcore50_core *core = desc->core;
	unsigned long flags_state;

	elcore50_write(DBDCSR_WRE, core, DSP_DBDCSR);
#ifndef ELCORE50_NO_IRQS
	elcore50_write(DQSTR_STP | DQSTR_ERRS, core, DSP_DMASKR);
	desc->core_stopped = 0;
#endif
	spin_lock_irqsave(&desc->state_lock, flags_state);
	desc->state = ELCORE50_JOB_STATUS_RUN;
	spin_unlock_irqrestore(&desc->state_lock, flags_state);
	elcore50_write(DCSR_RUN, core, DSP_DCSR);
}

#ifndef ELCORE50_NO_IRQS
static int event_handler(struct elcore50_job_inst_desc *desc, int ended)
{
	struct elcore50_core *core = desc->core;
	uint32_t reg_tmp;
	unsigned long flags_state;
	int debug_request, ret, debug_id;
	int debug_stopped = 0;

	if (desc->debug_state != ELCORE50_DBG_INTERRUPTED && !ended)
		elcore50_core_run(desc);

	if (irq_timeout_msec)
		ret = !wait_event_timeout(desc->irq_waitq,
			desc->core_stopped || desc->abort ||
				(desc->debug_request != DBG_REQUEST_NONE),
			msecs_to_jiffies(irq_timeout_msec));
	else {
		wait_event(desc->irq_waitq,
			   desc->core_stopped || desc->abort ||
				(desc->debug_request != DBG_REQUEST_NONE));
		ret = 0;
	}

	if (desc->step_breakpoint)
		debug_request = DBG_REQUEST_NONE;
	else
		debug_request = desc->debug_request;

	if (!desc->core_stopped && (debug_request != DBG_REQUEST_NONE))
		elcore50_write(elcore50_read(core, DSP_DCSR) & (~DCSR_RUN),
			       core, DSP_DCSR);

	if (ret || desc->abort) {
		elcore50_core_abort(core);
		elcore50_write(0, core, DSP_DMASKR);
		ended = 1;
		desc->stop_reason = ELCORE50_STOP_REASON_APP_EXCEPTION;
	}

	reg_tmp = elcore50_read(core, DSP_DQSTR);
	if ((desc->debug_state != ELCORE50_DBG_INTERRUPTED) &&
	     desc->core_stopped && ((reg_tmp & (DQSTR_SC|DQSTR_DBG)) == 0)) {
		ended = 1;
		desc->stop_reason = ELCORE50_STOP_REASON_APP_EXCEPTION;
	}
	// In case of wrong syscall number DSP will be stopped
	if (!ended && (reg_tmp & DQSTR_SC) != 0 && syscall_handler(desc)) {
		ended = 1;
		desc->stop_reason = ELCORE50_STOP_REASON_APP_EXCEPTION;
	}
	if (reg_tmp & DQSTR_DBG) {
		if (desc->attached) {
			desc->debug_state = ELCORE50_DBG_INTERRUPTED;
			debug_stopped = 1;
			debug_id = elcore50_read(core, DBG_INDEX) & DBG_ID;
			switch (debug_id) {
			case DBG_ID_DBSAR0:
			case DBG_ID_DBSAR1:
			case DBG_ID_DBSAR2:
			case DBG_ID_DBSAR3:
				desc->stop_reason =
					ELCORE50_STOP_REASON_HW_BREAKPOINT;
				break;
			case DBG_ID_DBCNTR:
				desc->stop_reason = ELCORE50_STOP_REASON_STEP;
				break;
			case DBG_ID_DBBREAK:
				desc->stop_reason =
					ELCORE50_STOP_REASON_SW_BREAKPOINT;
				break;
			case DBG_ID_QLIC:
				desc->stop_reason =
					ELCORE50_STOP_REASON_EXTERNAL_REQUEST;
				break;
			}

			elcore50_write(
				elcore50_read(core, DSP_IRQR) & (~IRQR_DBG),
				core, DSP_IRQR);
			elcore50_write(
				elcore50_read(core, DSP_DQSTR) & (~DQSTR_DBG),
				core, DSP_DQSTR);
		} else {
			ended = 1;
			desc->stop_reason = ELCORE50_STOP_REASON_APP_EXCEPTION;
		}
	}

	if (debug_stopped && desc->step_breakpoint &&
			(elcore50_read(core, DSP_DBCNTR) != 0)) {
		elcore50_write(desc->dbsar_value, core, desc->dbsar_addr);
		desc->step_breakpoint = 0;
		desc->dbcnt_rest_plus_1 = 0;
	}

	if (desc->step_breakpoint && (elcore50_read(core, DSP_DBCNTR) == 0)) {
		if (desc->dbcnt_rest_plus_1 != 1)
			desc->debug_state = ELCORE50_DBG_RUN;
		if (desc->dbcnt_rest_plus_1)
			elcore50_write(desc->dbcnt_rest_plus_1 - 1, core,
				       DSP_DBCNTR);
		elcore50_write(desc->dbsar_value, core, desc->dbsar_addr);
		desc->step_breakpoint = 0;
		desc->dbcnt_rest_plus_1 = 0;
	}

	switch (debug_request) {
	case DBG_REQUEST_IOCTL:
		desc->debug_request = DBG_READY_TO_PROCESS;
		wake_up(&desc->debug_waitq);
		wait_event(desc->irq_waitq,
			   desc->debug_request == DBG_PROCESSED);
	break;
	case DBG_REQUEST_ATTACH:
		if (desc->attached)
			desc->debug_result = -EBUSY;
		else {
			desc->debug_state = ELCORE50_DBG_INTERRUPTED;
			desc->stop_reason = ELCORE50_STOP_REASON_DBG_INTERRUPT;
			desc->attached = 1;
			desc->debug_result = 0;
		}
		break;
	case DBG_REQUEST_DETACH:
		if (!desc->attached)
			desc->debug_result = -EINVAL;
		else {
			desc->debug_state = ELCORE50_DBG_RUN;
			desc->attached = 0;
			desc->debug_result = 0;
		}
		break;
	case DBG_REQUEST_NONE:
		break;
	}

	spin_lock_irqsave(&desc->state_lock, flags_state);
	if ((desc->step_breakpoint == 0) &&
			(desc->debug_state == ELCORE50_DBG_INTERRUPTED)) {
		desc->state = ELCORE50_JOB_STATUS_INTERRUPTED;
		wake_up(&desc->poll_dbg_waitq);
	} else if (desc->debug_state == ELCORE50_DBG_RUN) {
		desc->state = ELCORE50_JOB_STATUS_RUN;
	}
	spin_unlock_irqrestore(&desc->state_lock, flags_state);

	if (debug_request != DBG_REQUEST_NONE) {
		desc->debug_request = DBG_REQUEST_NONE;
		wake_up(&desc->debug_waitq);
	}
	return ended;
}
#else
//TODO: Implement for noninterrupt mode
#endif

void elcore50_job_inst_run(struct work_struct *worker)
{
	unsigned long flags_state, flags_queue;
	int ret;
	int ended = 0;
#ifdef ELCORE50_NO_IRQS
	uint32_t irq_status;
	uint32_t reg_tmp;
#endif
	off_t offset;
	struct elcore50_job_inst_desc *desc = container_of(worker,
					struct elcore50_job_inst_desc,
					worker);
	struct elcore50_core *core = desc->core;
	struct cluster_priv *drv_priv = core->drv_priv;

	ret = elcore50_mmu_fill_args(desc);
	if (ret) {
		dev_err(core->dev,
			"Failed to fill MMU for job arguments. The job will be skiped\n");
		spin_lock_irqsave(&desc->state_lock, flags_state);
		desc->error = ELCORE50_JOB_STATUS_ERROR;
		spin_unlock_irqrestore(&desc->state_lock, flags_state);
		goto done;
	}
	elcore50_mmu_sync(desc);

	caches_setup(desc);
	caches_inval(desc);

	elcore50_write_regs(desc);
	if (desc->job_desc->pram) {
		offset = desc->job_desc->pram->vaddr_mmu_dsp -
				PHYS_INTERNAL_PRAM_DSP;
		elcore50_buf_cpy(drv_priv, core->pram + offset,
				 desc->job_desc->pram->mapper->vaddr,
				 desc->job_desc->pram->mapper->size);
	}
	if (desc->job_desc->xyram) {
		offset = desc->job_desc->xyram->vaddr_mmu_dsp -
				PHYS_INTERNAL_DSP;
		elcore50_buf_cpy(drv_priv, core->xyram + offset,
				 desc->job_desc->xyram->mapper->vaddr,
				 desc->job_desc->xyram->mapper->size);
	}

	spin_lock_irqsave(&desc->state_lock, flags_state);
	if (desc->debug_state == ELCORE50_DBG_INTERRUPTED) {
		desc->state = ELCORE50_JOB_STATUS_INTERRUPTED;
		wake_up(&desc->poll_dbg_waitq);
	}
	spin_unlock_irqrestore(&desc->state_lock, flags_state);

#ifndef ELCORE50_NO_IRQS
	while (1) {
		ended = event_handler(desc, ended);
		if (ended) {
			desc->step_breakpoint = 0;
			if (!desc->attached)
				break;
			desc->debug_state = ELCORE50_DBG_INTERRUPTED;
			desc->stop_reason = ELCORE50_STOP_REASON_APP_EXCEPTION;
		}
	}
#else
	// TODO: Implement event_handler
	reg_tmp = (DQSTR_STP | DQSTR_ERRS);
	while (1) {
		if (irq_timeout_msec)
			ret = elcore50_pollreg_timeout(core, DSP_DQSTR,
						       irq_status,
						       (irq_status & reg_tmp)
							     || desc->abort,
						       20000,
						       irq_timeout_msec *
								1000);
		else
			ret = elcore50_pollreg(core, DSP_DQSTR, irq_status,
					       (irq_status & reg_tmp) ||
							desc->abort,
					       20000);
		if ((irq_status & DQSTR_SC) == 0)
			break;
		// In case of wrong syscall number DSP will be stopped
		if (syscall_handler(desc))
			break;
		elcore50_core_run(desc);
	}
	if (desc->abort || ret)
		elcore50_core_abort(core);
#endif
	desc->debug_result = -EINVAL;
	desc->debug_state = ELCORE50_DBG_EXITED;
	wake_up(&desc->debug_waitq);

	elcore50_write(elcore50_read(core, DSP_DCSR) & (~DCSR_RUN), core,
		       DSP_DCSR);
	caches_flush_after_run(desc);
	if (desc->abort || ret) {
		dev_err(core->dev, ret ? "job timed out\n" : "job aborted\n");
		spin_lock_irqsave(&desc->state_lock, flags_state);
		desc->error = ELCORE50_JOB_STATUS_ERROR;
		spin_unlock_irqrestore(&desc->state_lock, flags_state);
	} else
		get_job_inst_results(desc);
	if (desc->job_desc->xyram) {
		offset = desc->job_desc->xyram->vaddr_mmu_dsp -
				PHYS_INTERNAL_DSP;
		memcpy_fromio(desc->job_desc->xyram->mapper->vaddr,
			      core->xyram + offset,
			      desc->job_desc->xyram->mapper->size);
	}
	elcore50_core_reset(core);
	elcore50_mmu_free_args(desc);
done:
	spin_lock_irqsave(&core->queue_lock, flags_queue);
	list_del(&desc->queue_node);
	spin_lock_irqsave(&desc->state_lock, flags_state);
	desc->state = ELCORE50_JOB_STATUS_DONE;
	spin_unlock_irqrestore(&desc->state_lock, flags_state);
	spin_unlock_irqrestore(&core->queue_lock, flags_queue);
	wake_up(&desc->poll_waitq);
}

long elcore50_get_job_inst_status(struct elcore50_core *core, void __user *arg)
{
	struct fd fd;
	struct elcore50_job_inst_desc *desc;
	struct elcore50_job_instance_status *status;
	int ret = 0;

	status = kzalloc(sizeof(struct elcore50_job_instance_status),
			 GFP_KERNEL);
	if (!status)
		return -ENOMEM;

	ret = copy_from_user(status, arg,
			     sizeof(struct elcore50_job_instance_status));
	if (ret) {
		ret = -EACCES;
		goto clean_status;
	}
	fd = fdget(status->job_instance_fd);
	if (!fd.file || fd.file->f_op != &elcore50_job_inst_fops) {
		ret = -EBADFD;
		WARN_ON(1);
		goto clean_fd;
	}

	desc = fd.file->private_data;

	status->state = desc->state;
	status->error = desc->error;

	ret = copy_to_user(arg, status,
			   sizeof(struct elcore50_job_instance_status));
clean_fd:
	fdput(fd);
clean_status:
	kfree(status);
	return ret;
}

/* Translate DSP virtual address to CPU virtual address */
void *elcore50_map_from_users(struct elcore50_job_inst_desc *desc,
			      u64 vaddr_mmu_dsp,
			      struct userptr_mapper **out_mapper,
			      size_t *offset, u64 *user_vaddr_cpu,
			      size_t size)
{
	struct page_entry *p = desc->job_desc->p_top;
	u64 index, j;
	void *retval;
	u8 inpage_offset = 38;
	struct userptr_mapper *mapper;
	struct elcore50_buffer_priv *buf_priv;
	struct elcore50_core *core = desc->core;

	// Get inpage offset
	for (j = 3; j >= 0; j--) {
		index = (vaddr_mmu_dsp >> (E50_PAGE_SHIFT + j * 9)) &
				GENMASK(8, 0);
		p = p + index;
		if (p->next_lvl == NULL)
			break;
		p = p->next_lvl;
		inpage_offset -= 9;
	}
	if ((p == NULL) || (p->mapper == NULL)) {
		WARN_ON(1);
		return NULL;
	}
	mapper = p->mapper;

	if (mapper->dmabuf->ops != &elcore50_dmabuf_ops) {
		dev_err(core->dev, "Attempt to map external buffer\n");
		return NULL;
	}
	buf_priv = mapper->dmabuf->priv;

	*out_mapper = mapper;
	if (!mapper->vaddr)
		mapper->vaddr = dma_buf_vmap(mapper->attach->dmabuf);
	retval = mapper->vaddr + p->offset - mapper->offset +
			(vaddr_mmu_dsp & GENMASK(inpage_offset, 0));
	*offset = retval - mapper->vaddr;
	if (buf_priv->buf_info.p == 0)
		*user_vaddr_cpu = 0;
	else
		*user_vaddr_cpu = buf_priv->buf_info.p + *offset;

	// Invalidate CPU caches
	sync_buffer(core, size, *offset, mapper, ELCORE50_BUF_SYNC_DIR_TO_CPU);

	return retval;
}

int elcore50_get_job_inst_count(struct elcore50_core *core, void __user *arg)
{
	struct elcore50_job_inst_desc *desc;
	u32 count;
	int ret;
	unsigned long queue_flags;

	count = 0;
	spin_lock_irqsave(&core->queue_lock, queue_flags);
	list_for_each_entry(desc, &core->job_queue, queue_node) {
		count += 1;
	}
	spin_unlock_irqrestore(&core->queue_lock, queue_flags);

	ret = copy_to_user(arg, &count, sizeof(u32));
	if (ret)
		return ret;
	return 0;
}

int elcore50_get_job_inst_list(struct elcore50_core *core, void __user *arg)
{
	struct elcore50_job_inst_desc *desc;
	struct elcore50_job_instance_info list_elem;
	struct elcore50_job_instance_list list;
	int ret = 0;
	u32 count = 0;
	unsigned long queue_flags;

	ret = copy_from_user(&list, arg,
			     sizeof(struct elcore50_job_instance_list));
	if (ret)
		return -EACCES;

	spin_lock_irqsave(&core->queue_lock, queue_flags);
	list_for_each_entry(desc, &core->job_queue, queue_node) {
		if (count == list.job_instance_count)
			break;
		list_elem.id = hash_long((u64)desc, sizeof(long) * 8);
		list_elem.pid = desc->pid;
		strcpy(list_elem.name, desc->name);
		ret = copy_to_user(&list.info[count], &list_elem,
				   sizeof(struct elcore50_job_instance_info));
		if (ret)
			goto unlock_restore;
		count += 1;
	}

	list.job_instance_ret = count;

	ret = copy_to_user(arg, &list,
			   sizeof(struct elcore50_job_instance_list));
unlock_restore:
	spin_unlock_irqrestore(&core->queue_lock, queue_flags);
	return ret;
}
