// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020-2021 RnD Center "ELVEES", JSC
 */

#include <linux/anon_inodes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "elcore50-mmu.h"

const struct file_operations elcore50_job_fops;

static int elcore50_job_release(struct inode *inode, struct file *file)
{
	int i;
	struct elcore50_job_desc *desc = file->private_data;

	elcore50_mmu_free(desc);

	fput(desc->stack_file);
	for (i = 0; i < desc->num_elf_sections; ++i) {
		kfree(desc->elf[i]);
		fput(desc->section_files[i]);
	}

	fput(desc->elcore50_file);
	kfree(desc->section_files);
	kfree(desc->elf);
	kfree(desc->stack);
	kfree(desc->xyram);
	kfree(desc->pram);
	kfree(desc);
	return 0;
}

const struct file_operations elcore50_job_fops = {
	.release = elcore50_job_release
};

static int parse_stack(struct elcore50_job_desc *desc, int stack_fd)
{
	struct userptr_mapper *mapper;
	int ret;
	struct fd fd;

	fd = fdget(stack_fd);
	if (!fd.file || fd.file->f_op != &elcore50_mapper_ops) {
		ret = -EINVAL;
		goto parse_err;
	}

	desc->stack = kzalloc(sizeof(struct elcore50_buf_desc), GFP_KERNEL);
	if (!desc->stack) {
		ret = -EINVAL;
		goto parse_err;
	}

	desc->stack_file = get_file(fd.file);
	mapper = fd.file->private_data;
	if (!mapper->vaddr)
		mapper->vaddr = dma_buf_vmap(mapper->attach->dmabuf);
	desc->stack->mapper = mapper;
	desc->stack->wr_addr = 0;
	desc->stack->type = ELCORE50_TYPE_GLOBAL_MEMORY;

	fdput(fd);
	return 0;
parse_err:
	fdput(fd);
	fput(desc->stack_file);
	return ret;
}

int elcore50_create_job(struct file *file, void __user *arg)
{
	struct elcore50_core *core =
		(struct elcore50_core *) file->private_data;
	struct elcore50_job_desc *desc;
	struct elcore50_job *job;
	int ret, i;
	struct fd fd;

	desc = kzalloc(sizeof(struct elcore50_job_desc),
		       GFP_KERNEL | __GFP_ZERO);
	job = kzalloc(sizeof(struct elcore50_job), GFP_KERNEL);

	if (!desc || !job) {
		ret = ENOMEM;
		goto clean_kfree;
	}
	ret = copy_from_user(job, arg, sizeof(struct elcore50_job));
	if (ret) {
		ret = -EACCES;
		goto clean_kfree;
	}
	desc->core = core;
	desc->hugepages = job->hugepages;

	desc->elcore50_file = get_file(file);

	ret = parse_stack(desc, job->stack_fd);
	if (ret)
		goto clean_kfree;

	if (job->num_elf_sections) {
		desc->elf = kcalloc(job->num_elf_sections,
				    sizeof(struct elcore50_buf_desc *),
				    GFP_KERNEL | __GFP_ZERO);
		if (!desc->elf) {
			ret = -ENOMEM;
			goto clean_stack;
		}

		desc->section_files = kcalloc(job->num_elf_sections,
					      sizeof(struct file *),
					      GFP_KERNEL);
		if (!desc->section_files) {
			ret = -ENOMEM;
			kfree(desc->elf);
			goto clean_stack;
		}
	} else {
		ret = -EINVAL;
		goto clean_stack;
	}

	for (i = 0; i < job->num_elf_sections; i++) {
		struct elcore50_job_elf_section *esect = &job->elf_sections[i];

		if (esect->type > ELCORE50_ELF_SECTION_LAST)
			return -EINVAL;

		fd = fdget(job->elf_sections[i].mapper_fd);
		if (!fd.file || fd.file->f_op != &elcore50_mapper_ops) {
			ret = -EINVAL;
			fdput(fd);
			goto clean_elf;
		}

		desc->elf[i] = kzalloc(sizeof(struct elcore50_buf_desc),
				       GFP_KERNEL);
		if (!desc->elf[i]) {
			ret = -ENOMEM;
			goto clean_fd;
		}

		desc->section_files[i] = get_file(fd.file);
		desc->elf[i]->mapper = fd.file->private_data;
		desc->elf[i]->wr_addr = 0;
		desc->elf[i]->type = esect->type;
		desc->elf[i]->vaddr_mmu_dsp = esect->elcore_virtual_address;
		if (desc->elf[i]->mapper->offset ||
				desc->elf[i]->vaddr_mmu_dsp &
					E50_INPAGE_MASK) {
			dev_err(core->dev,
				"Both user_space_address and elcore_virtual_address must be aligned to 4K\n");
			return -EINVAL;
		}
		desc->num_elf_sections = i + 1;
		fdput(fd);
	}

	desc->dsp_pool = mmu_pool_create(ilog2(E50_PAGE_SIZE), -1);
	if (IS_ERR(desc->dsp_pool)) {
		ret = PTR_ERR(desc->dsp_pool);
		goto clean_elf;
	}

	ret = mmu_pool_add(desc->dsp_pool, ELCORE50_VADDR_START, 1UL << 32,
			   -1);
	if (ret)
		goto clean_elfpool;

	ret = elcore50_mmu_fill(desc);
	if (ret)
		goto clean_elfpool;

	ret = anon_inode_getfd("elcorejob", &elcore50_job_fops, desc, O_RDWR);
	if (ret < 0)
		goto clean_mmu;
	job->job_fd = ret;

	ret = copy_to_user(arg, job, sizeof(struct elcore50_job));
	if (ret) {
		ret = -EACCES;
		goto clean_fd;
	}
	return 0;
clean_fd:
	put_unused_fd(job->job_fd);
clean_mmu:
	elcore50_mmu_free(desc);
clean_elfpool:
	mmu_pool_destroy(desc->dsp_pool);
clean_elf:
	for (i = 0; i < desc->num_elf_sections; ++i)
		fput(desc->section_files[i]);
	kfree(desc->section_files);
	kfree(desc->elf);
clean_stack:
	fput(desc->stack_file);
clean_kfree:
	fput(desc->elcore50_file);
	kfree(desc);
	kfree(job);
	return ret;
}
