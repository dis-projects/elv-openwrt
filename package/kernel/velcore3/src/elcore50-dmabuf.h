/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_ELCORE50_DMABUF_H
#define _LINUX_ELCORE50_DMABUF_H

#include <linux/dma-buf.h>
#include <linux/scatterlist.h>

#include "elcore50-core.h"

struct elcore50_buffer_priv {
	/* common part */
	struct elcore50_buf buf_info;
	struct dma_buf dmabuf;
	struct cluster_priv *drv_priv;
	void *vaddr;

	/* noncached part */
	dma_addr_t paddr;

	/* cached part */
	unsigned int num_pages;
	struct page **pages;
	struct frame_vector *vec;
	struct sg_table *sgt;
	size_t size;
};

int elcore50_create_buffer(struct elcore50_core *core, void __user *arg);

#endif
