// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#include <linux/slab.h>

#include "elcore50-job.h"
#include "elcore50-mmu.h"

struct e50_protected_region {
	u32 base_addr;
	bool is_cluster_specific;
	u32 size;
};

#ifdef ELCORE50_MCOM03
static struct e50_protected_region protected_regions[] = {
{ 0x1800000, 0, 0x800000 }, // EPort
{ 0x2800000, 0, 0x40000}, // Registers
{ 0x2E00000, 0, 0x600000} // PRAM/XYRAM
};
#else
static struct e50_protected_region protected_regions[] = {
{ 0x10000000, 0, 0x2000000 }, // Registers
{ 0x13000000, 1, 0x100000 }, // QPRAM/QYRAM
{ 0x17000000, 1, 0x40000 } // QRegisters
};
#endif

static size_t MMU_PAGE_SIZES[] = {SZ_4K, SZ_2M, SZ_1G, 512 * SZ_1G};

static inline unsigned long elcore50_mmu_alloc_fixed(struct mmu_pool *pool,
						     size_t size,
						     unsigned long address)
{
	struct mmupool_data_fixed data;

	data.offset = address - ELCORE50_VADDR_START;
	return mmu_pool_alloc_algo(pool, size, mmu_pool_fixed_alloc, &data);
}

static inline void write_pte_entry(uint64_t *pte, dma_addr_t paddr,
				   enum pte_type type)
{
	uint64_t tmp;

	tmp = E50_PTE_V_MASK;
	tmp |= (paddr >> E50_PAGE_SHIFT) << E50_PTE_PADDR_SHIFT;
	tmp |= (type << E50_PTE_TYPE_SHIFT) & E50_PTE_TYPE_MASK;
	/* FIXME: this is a hack - rf#10482 */
	if (type > PTE_NEXTGL)
		tmp |= E50_PTE_D_MASK | E50_PTE_R_MASK;
	*pte = tmp;
	pr_debug("pte %px paddr %llx type=%i res=%llx", pte, paddr, type, tmp);
}

static struct page_entry *get_page_entry(struct elcore50_core *core,
					 struct page_entry *p_top,
					 uint64_t vaddr_mmu_dsp,
					 enum elcore50_page_size ps,
					 bool is_48bit)
{
	int i, j;
	dma_addr_t paddr;
	struct page *page;
	struct page_entry *p = p_top, *p_cur;
	struct cluster_priv *drv_priv = core->drv_priv;
	uint64_t *pte;
	uint64_t index;
	/* 48-bit addresses don't work with elcore50 */
	if (vaddr_mmu_dsp >> (is_48bit ? 48 : 32)) {
		dev_err(core->dev, "Virtual address 0x%llx out of bounds\n",
			vaddr_mmu_dsp);
		return NULL;
	}
	for (j = VMMU_PAGE_MAX_LEVEL; j > ps; j--) {
		index = (vaddr_mmu_dsp >> (E50_PAGE_SHIFT + j * 9))
				& GENMASK(8, 0);

		p_cur = p + index;
		if (p_cur->next_lvl) {
			p->num_non_zero_ptes += 1;
			p = p_cur->next_lvl;
		}
		else {
			p_cur->next_lvl = kcalloc(E50_PTE_ENTRIES,
					      sizeof(struct page_entry),
					      GFP_KERNEL);
			if (!p_cur->next_lvl)
				return NULL;

			page = alloc_pages(GFP_KERNEL | __GFP_ZERO,
					   get_order(E50_PAGE_SIZE));
			if (!page)
				goto clean_next_lvl;
			pte = page_address(page);
			paddr = dma_map_single_attrs(drv_priv->dev, pte,
						     E50_PAGE_SIZE,
						     DMA_TO_DEVICE,
						     DMA_ATTR_SKIP_CPU_SYNC);
			if (!paddr)
				goto clean_page;
			p_cur->dma_addr = paddr;
			write_pte_entry(p_cur->pte, paddr, PTE_NEXT);
			p->num_non_zero_ptes += 1;
			p = p_cur->next_lvl;

			for (i = 0; i < E50_PTE_ENTRIES; i++)
				p[i].pte = &pte[i];
			continue;
clean_page:
			free_pages((unsigned long)pte,
				   get_order(E50_PAGE_SIZE));
clean_next_lvl:
			kfree(p_cur->next_lvl);
			p_cur->next_lvl = NULL;
			return NULL;
		}
	}
	/* Increment ptes counter for leaf node. write_pte_entry() will be
	 * called in write_buffer_pages()
	 */
	p->num_non_zero_ptes += 1;
	/* move the pointer to the leaf node rather than leaf page start */
	index = (vaddr_mmu_dsp >> (E50_PAGE_SHIFT + j * 9)) & GENMASK(8, 0);
	p_cur = p + index;
	return p_cur;
}

static int write_buffer_pages(struct elcore50_core *core, int hugepages,
			      struct page_entry *p_top,
			      uint64_t buf_vaddr_mmu_dsp, enum pte_type type,
			      dma_addr_t buf_paddr, size_t buf_size,
			      bool is_48bit, struct userptr_mapper *mapper,
			      uint64_t vaddr_start_mmu_dsp)
{
	size_t page_size;
	enum elcore50_page_size ps;
	struct page_entry *p;

	pr_debug("buf_paddr=%llx, vaddr=%llx, size=%lx\n",
		 buf_paddr, buf_vaddr_mmu_dsp, buf_size);
	WARN_ON(buf_paddr & E50_INPAGE_MASK);
	WARN_ON(buf_vaddr_mmu_dsp & E50_INPAGE_MASK);
	WARN_ON(buf_size & E50_INPAGE_MASK);
	while (buf_size > 0) {
		if (hugepages) {
			if (!(buf_vaddr_mmu_dsp & (SZ_1G - 1)) &&
					buf_size >= SZ_1G) {
				page_size = SZ_1G;
				ps = ELCORE50_PAGE_1G;
			} else if (!(buf_vaddr_mmu_dsp & (SZ_2M - 1)) &&
					buf_size >= SZ_2M) {
				page_size = SZ_2M;
				ps = ELCORE50_PAGE_2M;
			} else {
				page_size = SZ_4K;
				ps = ELCORE50_PAGE_4K;
			}
		} else {
			page_size = SZ_4K;
			ps = ELCORE50_PAGE_4K;
		}
		p = get_page_entry(core, p_top, buf_vaddr_mmu_dsp, ps,
				   is_48bit);
		if (!p)
			return -ENOMEM;
		p->mapper = mapper;
		p->offset = buf_vaddr_mmu_dsp - vaddr_start_mmu_dsp;

		write_pte_entry(p->pte, buf_paddr, type);
		buf_vaddr_mmu_dsp += page_size;
		buf_paddr += page_size;
		buf_size -= page_size;
	}
	return 0;
}

void sync_elcore_pte_table_for_device(struct elcore50_core *core,
				      struct page_entry *p)
{
	int i;
	struct page_entry *p_cur;
	uint64_t *pte;

	for (i = 0; i < E50_PTE_ENTRIES; i++) {
		p_cur = p + i;
		if (p_cur->next_lvl) {
			pte = p_cur->next_lvl->pte;
			sync_elcore_pte_table_for_device(core,
							 p_cur->next_lvl);
			if (p_cur->dma_addr) {
				dma_sync_single_for_device(core->drv_priv->dev,
							   p_cur->dma_addr,
							   E50_PAGE_SIZE,
							   DMA_TO_DEVICE);
			}
		}
	}
}

static int mmu_map_buffer(struct elcore50_core *core,
			   struct page_entry *p_top, int hugepages,
			   uint64_t vaddr_mmu_dsp,
			   struct elcore50_buf_desc *buf)
{
	/*
	 * the only userptr that specifies the vaddr is ELF, and addresses
	 * for it are reserved in the dsp_pool.
	 */
	/* TODO: sync the memory? create non-cacheable memory? */
	int rc = 0;
	enum pte_type type;
	uint64_t vaddr_start_mmu_dsp;
	int i;
	struct scatterlist *iter;
	struct userptr_mapper *mapper = buf->mapper;
	dma_addr_t dmastart;
	size_t dmalen, dma_offset;

	if (buf->wr_addr)
		*buf->wr_addr = vaddr_mmu_dsp + mapper->offset;

	switch (buf->type) {
	case ELCORE50_ELF_SECTION_CODE:
		type = PTE_SVRWXURWX;
		break;
	case ELCORE50_ELF_SECTION_DATA:
		type = PTE_SVRWXURWX;
		break;
	case ELCORE50_ELF_SECTION_DATA_CONST:
		type = PTE_SVRWXURWX;
	}
	vaddr_start_mmu_dsp = vaddr_mmu_dsp;
	for_each_sg(mapper->sgt->sgl, iter, mapper->sgt->nents, i) {
		dma_offset = sg_dma_address(iter) & E50_INPAGE_MASK;
		dmastart = sg_dma_address(iter) - dma_offset;
		dmalen = round_up(sg_dma_len(iter) + dma_offset,
				  E50_PAGE_SIZE);
		pr_debug("dmastart=%llx len=%lx ofst=%lx\n", dmastart, dmalen,
			 dma_offset);
		rc = write_buffer_pages(core, hugepages, p_top, vaddr_mmu_dsp,
					type, dmastart, dmalen,
					buf->arg_type ==
						ELCORE50_TYPE_DMA_MEMORY,
					mapper, vaddr_start_mmu_dsp);
		if (rc)
			return rc;
		vaddr_mmu_dsp += dmalen;
	}
	return rc;
}

static int mmu_map_elf(struct elcore50_job_desc *job_desc,
		       struct elcore50_buf_desc *elf)
{
	uint64_t vaddr_mmu_dsp;

	vaddr_mmu_dsp = elcore50_mmu_alloc_fixed(job_desc->dsp_pool,
						 elf->mapper->size_aligned,
						 elf->vaddr_mmu_dsp);
	if (!vaddr_mmu_dsp)
		return -ENOMEM;
	elf->vaddr_mmu_dsp = vaddr_mmu_dsp;
	elf->mmu_allocated = 1;
	return mmu_map_buffer(job_desc->core, job_desc->p_top,
			      job_desc->hugepages, vaddr_mmu_dsp, elf);
}

static int mmu_map_buf(struct elcore50_job_inst_desc *job_inst,
		       struct elcore50_buf_desc *buf)
{
	uint64_t vaddr_mmu_dsp;
	struct mmu_pool *pool;

	if (buf->arg_type == ELCORE50_TYPE_DMA_MEMORY)
		pool = job_inst->dma_pool;
	else
		pool = job_inst->dsp_pool;
	if (buf->arg_type == ELCORE50_TYPE_NC_GLOBAL_MEMORY) {
		vaddr_mmu_dsp = elcore50_mmu_alloc_fixed(
					pool, buf->mapper->size_aligned,
					job_inst->nc_mem_current);
		job_inst->nc_mem_current += buf->mapper->size_aligned;
	} else
		vaddr_mmu_dsp =
			mmu_pool_alloc(pool, buf->mapper->size_aligned);
	buf->vaddr_mmu_dsp = vaddr_mmu_dsp;
	if (!vaddr_mmu_dsp)
		return -ENOMEM;
	buf->mmu_allocated = 1;
	return mmu_map_buffer(job_inst->core, job_inst->job_desc->p_top,
			      job_inst->job_desc->hugepages, vaddr_mmu_dsp,
			      buf);
}

static void mmu_free_ptes_recursive(struct elcore50_core *core,
				    struct page_entry *p)
{
	int i;
	struct page_entry *p_cur;
	uint64_t *pte;

	for (i = 0; i < E50_PTE_ENTRIES; i++) {
		p_cur = p + i;
		if (p_cur->next_lvl) {
			pte = p_cur->next_lvl->pte;
			mmu_free_ptes_recursive(core, p_cur->next_lvl);
			if (pte) {
				dma_unmap_single_attrs(core->drv_priv->dev,
						       p_cur->dma_addr,
						       E50_PAGE_SIZE,
						       DMA_FROM_DEVICE,
						       DMA_ATTR_SKIP_CPU_SYNC);
				free_pages((unsigned long)pte,
					   get_order(E50_PAGE_SIZE));
			}
		}
	}
	kfree(p);
}

static void elcore50_mmu_free_fixed(struct elcore50_job_desc *job_desc)
{
	int cluster_idx, i, size;
	unsigned long addr;

	size = sizeof(protected_regions) / sizeof(struct e50_protected_region);
	cluster_idx = IDR_CLUSTER(elcore50_read(job_desc->core, DSP_IDR));

	for (i = size - 1; i >= 0; i--) {
		addr = protected_regions[i].base_addr;
		if (protected_regions[i].is_cluster_specific)
			addr += cluster_idx * protected_regions[i].size;

		mmu_pool_free(job_desc->dsp_pool, addr,
			      protected_regions[i].size);
	}
}

static int elcore50_mmu_fill_fixed(struct elcore50_job_desc *job_desc)
{
	int cluster_idx, i, size;
	unsigned long addr;

	size = sizeof(protected_regions) / sizeof(struct e50_protected_region);
	cluster_idx = IDR_CLUSTER(elcore50_read(job_desc->core, DSP_IDR));

	for (i = 0; i < size; ++i) {
		addr = protected_regions[i].base_addr;
		if (protected_regions[i].is_cluster_specific)
			addr += cluster_idx * protected_regions[i].size;

		addr = elcore50_mmu_alloc_fixed(job_desc->dsp_pool,
						protected_regions[i].size,
						addr);
		if (!addr)
			goto fixed_alloc_err;
	}
	return 0;

fixed_alloc_err:
	while (i) {
		addr = protected_regions[i - 1].base_addr;
		if (protected_regions[i - 1].is_cluster_specific)
			addr += cluster_idx * protected_regions[i - 1].size;

		mmu_pool_free(job_desc->dsp_pool, addr,
			      protected_regions[i - 1].size);
		i--;
	}
	return -ENOMEM;
}

static int elcore50_is_addr_xyram(struct elcore50_job_desc *job_desc,
				  struct elcore50_buf_desc *elf)
{
	unsigned long start, end;

	start = elf->vaddr_mmu_dsp;
	end = start + elf->mapper->size;

	if ((start >= PHYS_INTERNAL_DSP) &&
		(end <= (PHYS_INTERNAL_INTERLEAVE_DSP + INTERNAL_DSP_SIZE))) {
		return 1;
	}
	return 0;
}

static void elcore50_prepare_xyram(struct elcore50_job_desc *job_desc,
				   struct elcore50_buf_desc *elf)
{
	struct userptr_mapper *mapper = elf->mapper;

	if (!mapper->vaddr)
		mapper->vaddr = dma_buf_vmap(mapper->attach->dmabuf);

	job_desc->xyram = kzalloc(sizeof(struct elcore50_buf_desc),
				  GFP_KERNEL);
	job_desc->xyram->mapper = elf->mapper;
	job_desc->xyram->vaddr_mmu_dsp = elf->vaddr_mmu_dsp;
}

static int elcore50_is_addr_pram(struct elcore50_job_desc *job_desc,
				 struct elcore50_buf_desc *elf)
{
	unsigned long start, end;

	start = elf->vaddr_mmu_dsp;
	end = start + elf->mapper->size;

	if ((start >= PHYS_INTERNAL_PRAM_DSP) &&
		(end <= (PHYS_INTERNAL_PRAM_DSP + INTERNAL_DSP_PRAM_SIZE))) {
		return 1;
	}
	return 0;
}

static void elcore50_prepare_pram(struct elcore50_job_desc *job_desc,
				  struct elcore50_buf_desc *elf)
{
	struct userptr_mapper *mapper = elf->mapper;

	if (!mapper->vaddr)
		mapper->vaddr = dma_buf_vmap(mapper->attach->dmabuf);

	job_desc->pram = kzalloc(sizeof(struct elcore50_buf_desc), GFP_KERNEL);
	job_desc->pram->mapper = elf->mapper;
	job_desc->pram->vaddr_mmu_dsp = elf->vaddr_mmu_dsp;
}

void elcore50_mmu_free(struct elcore50_job_desc *job_desc)
{
	int i;
	struct elcore50_buf_desc *elf;

	dma_unmap_single_attrs(job_desc->core->drv_priv->dev,
			       job_desc->pt4_dma_addr,
			       E50_PAGE_SIZE, DMA_TO_DEVICE,
			       DMA_ATTR_SKIP_CPU_SYNC);

	mmu_free_ptes_recursive(job_desc->core, job_desc->p_top);
	free_pages((unsigned long)job_desc->pt4, get_order(E50_PAGE_SIZE));

	for (i = 0; i < job_desc->num_elf_sections; i++) {
		elf = job_desc->elf[i];
		if (elcore50_is_addr_xyram(job_desc, elf))
			continue;
		if (elcore50_is_addr_pram(job_desc, elf))
			continue;
		mmu_pool_free(job_desc->dsp_pool, elf->vaddr_mmu_dsp,
			      elf->mapper->size_aligned);
	}
	elcore50_mmu_free_fixed(job_desc);
	mmu_pool_free(job_desc->dsp_pool, job_desc->stack->vaddr_mmu_dsp,
		      job_desc->stack->mapper->size_aligned);
}

static int mmu_free_recursive_mapper(struct elcore50_core *core,
				      struct page_entry *p,
				      uint64_t vaddr_mmu_dsp,
				      uint32_t depth,
				      size_t *freed)
{
	struct page_entry *p_cur, *p_next;
	u64 index;
	int i, rc;

	WARN_ON(depth > VMMU_PAGE_MAX_LEVEL);

	index = (vaddr_mmu_dsp >> (E50_PAGE_SHIFT + depth * 9)) & GENMASK(8, 0);
	p_cur = p + index;

	if (p_cur->next_lvl) {
		rc = mmu_free_recursive_mapper(core, p_cur->next_lvl,
					       vaddr_mmu_dsp, depth - 1,
					       freed);

		if (rc == 0) {
			p->num_non_zero_ptes -= 1;
			*p_cur->pte = 0;
			p_cur->next_lvl = NULL;
			p_cur->mapper = NULL;
		}
	} else {
		p->num_non_zero_ptes -= 1;
		*p_cur->pte = 0;
		*freed += MMU_PAGE_SIZES[depth];
		for (i = index + 1; i < E50_PTE_ENTRIES; ++i) {
			p_next = p + i;
			if (p_next->mapper != p_cur->mapper)
				break;
			*freed += MMU_PAGE_SIZES[depth];
			p->num_non_zero_ptes -= 1;
			*p_next->pte = 0;
			p_next->mapper = NULL;
		}
		p_cur->mapper = NULL;
	}

	if (p->num_non_zero_ptes == 0) {
		dma_unmap_single_attrs(core->drv_priv->dev, p_cur->dma_addr,
				       E50_PAGE_SIZE, DMA_FROM_DEVICE,
				       DMA_ATTR_SKIP_CPU_SYNC);
		free_pages((unsigned long)p->pte, get_order(E50_PAGE_SIZE));
		kfree(p);
		return 0;
	}
	return p->num_non_zero_ptes;
}

static void mmu_free_mappers(struct elcore50_job_inst_desc *job_inst)
{
	struct page_entry *p_cur = job_inst->job_desc->p_top;
	uint64_t vaddr_mmu_dsp;
	struct elcore50_core *core = job_inst->core;
	struct elcore50_buf_desc *buf;
	size_t buf_size, released;
	int i;

	for (i = 0; i < job_inst->argc; i++) {
		buf = job_inst->args[i];
		vaddr_mmu_dsp = buf->vaddr_mmu_dsp;
		buf_size = buf->mapper->size_aligned;
		while (buf_size > 0) {
			released = 0;
			mmu_free_recursive_mapper(core, p_cur, vaddr_mmu_dsp,
						  VMMU_PAGE_MAX_LEVEL,
						  &released);
			if (!released) {
				WARN_ON(1);
				return;
			}
			vaddr_mmu_dsp += released;
			buf_size -= released;
		}
	}
}

void elcore50_mmu_free_args(struct elcore50_job_inst_desc *job_inst)
{
	int i;
	struct elcore50_buf_desc *buf;

	mmu_free_mappers(job_inst);

	for (i = 0; i < job_inst->argc; i++) {
		buf = job_inst->args[i];
		if (buf->arg_type == ELCORE50_TYPE_DMA_MEMORY)
			mmu_pool_free(job_inst->dma_pool,
				      buf->vaddr_mmu_dsp,
				      buf->mapper->size_aligned);
		else if (buf->arg_type == ELCORE50_TYPE_NC_GLOBAL_MEMORY)
			mmu_pool_free(job_inst->dsp_pool,
				      buf->vaddr_mmu_dsp,
				      buf->mapper->size_aligned);
		else
			mmu_pool_free(job_inst->dsp_pool,
				      buf->vaddr_mmu_dsp,
				      buf->mapper->size_aligned);
	}
}

static int mmu_map_stack(struct elcore50_job_desc *job_desc)
{
	uint64_t vaddr_mmu_dsp;
	struct elcore50_buf_desc *stack = job_desc->stack;
	struct userptr_mapper *stack_mapper = stack->mapper;

	vaddr_mmu_dsp = mmu_pool_alloc(job_desc->dsp_pool,
				       stack_mapper->size_aligned);
	stack->vaddr_mmu_dsp = vaddr_mmu_dsp;
	if (!vaddr_mmu_dsp)
		return -ENOMEM;
	stack->mmu_allocated = 1;
	return mmu_map_buffer(job_desc->core, job_desc->p_top,
			      job_desc->hugepages, vaddr_mmu_dsp, stack);
}

void elcore50_mmu_sync(struct elcore50_job_inst_desc *job_inst)
{
	dma_sync_single_for_device(job_inst->core->drv_priv->dev,
				   job_inst->job_desc->pt4_dma_addr,
				   E50_PAGE_SIZE, DMA_TO_DEVICE);
	sync_elcore_pte_table_for_device(job_inst->core,
					 job_inst->job_desc->p_top);
}

int elcore50_mmu_fill(struct elcore50_job_desc *job_desc)
{
	int i, rc = 0;
	uint64_t *pt4;
	struct page_entry *p_top;
	struct page *page;

	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(E50_PAGE_SIZE));
	if (!page)
		return -ENOMEM;
	pt4 = page_address(page);
	job_desc->pt4 = pt4;
	job_desc->pt4_dma_addr = dma_map_single_attrs(
						job_desc->core->drv_priv->dev,
						pt4, E50_PAGE_SIZE,
						DMA_TO_DEVICE,
						DMA_ATTR_SKIP_CPU_SYNC);
	if (!job_desc->pt4_dma_addr) {
		free_pages((unsigned long)pt4, get_order(E50_PAGE_SIZE));
		return -ENOMEM;
	}

	p_top = kcalloc(E50_PTE_ENTRIES, sizeof(struct page_entry),
			GFP_KERNEL);
	if (!p_top) {
		rc = -ENOMEM;
		goto clean_pt4;
	}
	job_desc->p_top = p_top;
	for (i = 0; i < E50_PTE_ENTRIES; i++)
		p_top[i].pte = &pt4[i];

	rc = elcore50_mmu_fill_fixed(job_desc);
	if (rc) {
		kfree(p_top);
		goto clean_pt4;
	}

	for (i = 0; i < job_desc->num_elf_sections; i++) {
		if (elcore50_is_addr_xyram(job_desc, job_desc->elf[i])) {
			elcore50_prepare_xyram(job_desc, job_desc->elf[i]);
			continue;
		}
		if (elcore50_is_addr_pram(job_desc, job_desc->elf[i])) {
			elcore50_prepare_pram(job_desc, job_desc->elf[i]);
			continue;
		}
		rc = mmu_map_elf(job_desc, job_desc->elf[i]);
		if (rc != 0)
			goto clean_elf;
	}

	rc = mmu_map_stack(job_desc);
	if (rc)
		goto clean_stack;

	return 0;
clean_stack:
	if (job_desc->stack->vaddr_mmu_dsp)
		mmu_pool_free(job_desc->dsp_pool,
			      job_desc->stack->vaddr_mmu_dsp,
			      job_desc->stack->mapper->size_aligned);
clean_elf:
	for (i = 0; i < job_desc->num_elf_sections; i++) {
		if (job_desc->elf[i]->mmu_allocated)
			mmu_pool_free(job_desc->dsp_pool,
				      job_desc->elf[i]->vaddr_mmu_dsp,
				      job_desc->elf[i]->mapper->size_aligned);
	}
	mmu_free_ptes_recursive(job_desc->core, job_desc->p_top);
	elcore50_mmu_free_fixed(job_desc);
clean_pt4:
		dma_unmap_single_attrs(job_desc->core->drv_priv->dev,
				       (unsigned long)pt4, E50_PAGE_SIZE,
				       DMA_TO_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
		free_pages((unsigned long)pt4, get_order(E50_PAGE_SIZE));
	return rc;
}

int elcore50_mmu_fill_args(struct elcore50_job_inst_desc *job_inst)
{
	int i, rc = 0;
	struct elcore50_buf_desc *arg;
	struct userptr_mapper *mapper;
	uint64_t vaddr_mmu_dsp = 0;

	for (i = 0; i < job_inst->argc; i++) {
		arg = job_inst->args[i];
		if (arg->arg_type != ELCORE50_TYPE_NC_GLOBAL_MEMORY)
			continue;
		rc = mmu_map_buf(job_inst, arg);
		if (rc != 0)
			goto clean_args;
	}
	if (job_inst->nc_mem_current) {
		vaddr_mmu_dsp = elcore50_mmu_alloc_fixed(
				job_inst->dsp_pool,
				(1UL << 32) - job_inst->nc_mem_current,
				job_inst->nc_mem_current);
		if (!vaddr_mmu_dsp) {
			rc = -ENOMEM;
			goto clean_args;
		}
	}

	for (i = 0; i < job_inst->argc; i++) {
		arg = job_inst->args[i];
		if (arg->arg_type == ELCORE50_TYPE_NC_GLOBAL_MEMORY)
			continue;
		rc = mmu_map_buf(job_inst, arg);
		if (rc != 0)
			goto clean_args;
	}

	if (job_inst->nc_mem_current && vaddr_mmu_dsp) {
		mmu_pool_free(job_inst->dsp_pool, vaddr_mmu_dsp,
			      (1UL << 32) - job_inst->nc_mem_current);
	}
	return 0;
clean_args:
	for (i = 0; i < job_inst->argc; i++) {
		if (job_inst->args[i]->mmu_allocated) {
			arg = job_inst->args[i];
			mapper = arg->mapper;
			if (arg->arg_type == ELCORE50_TYPE_DMA_MEMORY)
				mmu_pool_free(job_inst->dma_pool,
					      arg->vaddr_mmu_dsp,
					      mapper->size_aligned);
			else
				mmu_pool_free(job_inst->dsp_pool,
					      arg->vaddr_mmu_dsp,
					      mapper->size_aligned);
		}
	}
	if (job_inst->nc_mem_current && vaddr_mmu_dsp) {
		mmu_pool_free(job_inst->dma_pool, vaddr_mmu_dsp,
			      (1UL << 32) - job_inst->nc_mem_current);
	}
	return rc;
}
