/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_ELCORE50_MAPPER_H
#define _LINUX_ELCORE50_MAPPER_H

#include "elcore50-dmabuf.h"

/**
 * struct userptr_mapper
 * @size: Actual buffer size
 * @size_aligned: Combined size of all 4K pages containing buffer
 * @offset: Offset from 4K boundary to actual buffer start address
 */
struct userptr_mapper {
	struct dma_buf_attachment *attach;
	struct sg_table *sgt;
	struct dma_buf *dmabuf;
	void *vaddr;
	size_t size;
	size_t size_aligned;
	unsigned int offset;
};

int sync_buffer(struct elcore50_core *core, size_t size, size_t buf_offset,
		struct userptr_mapper *mapper, enum elcore50_buf_sync_dir dir);
int elcore50_create_mapper(struct elcore50_core *core, void __user *arg);
int elcore50_sync_buffer(struct elcore50_core *core, void __user *arg);

#endif
