/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_ELCORE50_MMU_H
#define _LINUX_ELCORE50_MMU_H

#include "elcore50-job-instance.h"
#include "mmu-alloc.h"

enum elcore50_page_size {
	ELCORE50_PAGE_4K = 0,
	ELCORE50_PAGE_2M = 1,
	ELCORE50_PAGE_1G = 2,
	ELCORE50_PAGE_512G = 3
};

enum pte_type {
	PTE_NEXT = 0,
	PTE_NEXTGL = 1,
	PTE_SVROURX = 2,
	PTE_SVRWURWX = 3,
	PTE_SVROURO = 4,
	PTE_SVRWURW = 5,
	PTE_SVRXURX = 6,
	PTE_SVRWXURWX = 7,
	PTE_SVRO = 8,
	PTE_SVRW = 9,
	PTE_SVRX = 10,
	PTE_SVRWX = 11,
	PTE_SVROGL = 12,
	PTE_SVRWGL = 13,
	PTE_SVRXGL = 14,
	PTE_SVRWXGL = 15
};

struct page_entry {
	uint64_t *pte;
	struct page_entry *next_lvl;
	dma_addr_t dma_addr;
	struct userptr_mapper *mapper;
	size_t offset;
	size_t num_non_zero_ptes;
};

int elcore50_mmu_fill(struct elcore50_job_desc *job_desc);
void elcore50_mmu_free(struct elcore50_job_desc *job_desc);
int elcore50_mmu_fill_args(struct elcore50_job_inst_desc *job_inst);
void elcore50_mmu_free_args(struct elcore50_job_inst_desc *job_inst);
void elcore50_mmu_sync(struct elcore50_job_inst_desc *job_inst);

#endif
