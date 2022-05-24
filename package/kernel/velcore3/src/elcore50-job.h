/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020-2021 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_ELCORE50_JOB_H
#define _LINUX_ELCORE50_JOB_H

#include "elcore50-mapper.h"

struct elcore50_buf_desc {
	struct userptr_mapper *mapper;
	enum elcore50_job_elf_section_type type;
	enum elcore50_job_arg_type arg_type;
	uint64_t vaddr_mmu_dsp;
	int mmu_allocated;
	uint64_t *wr_addr;
};

/**
 * struct elcore50_job_desc
 */
struct elcore50_job_desc {
	struct elcore50_core *core;

	int num_elf_sections;
	struct elcore50_buf_desc **elf;
	struct file **section_files;

	struct elcore50_buf_desc *stack;
	struct file *stack_file;

	struct elcore50_buf_desc *pram;
	struct elcore50_buf_desc *xyram;

	struct file *elcore50_file;

	int hugepages;

	struct page_entry *p_top;
	uint64_t *pt4;
	dma_addr_t pt4_dma_addr;

	struct mmu_pool *dsp_pool;
};

int elcore50_create_job(struct file *file, void __user *arg);

#endif
