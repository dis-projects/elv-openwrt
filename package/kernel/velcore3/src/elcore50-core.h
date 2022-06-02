/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_ELCORE50_CORE_H
#define _LINUX_ELCORE50_CORE_H

#include <linux/cdev.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/types.h>

#include "elcore50.h"
#include "regs.h"

extern u32 reg_dump_enable;

struct cluster_priv {
	int ncores;
	int nirqs;
	dev_t dev_num;
	struct elcore50_core *cores;
	unsigned int *irqs;
	struct device *dev;
	void __iomem *mem;
	void __iomem *regs;
	struct reset_control *resets;
	int clock_count;
	struct clk **clocks;
};

struct elcore50_core {
	struct cluster_priv *drv_priv;
	int corenum;
	struct device *dev;
	struct cdev cdev;
	int cdev_idr;
	/* the list is used for a) telling interrupts which job is current and
	 * b) cleaning up all jobs on remove() */
	struct list_head job_queue;
	struct workqueue_struct *work_q;
	spinlock_t queue_lock;
	void __iomem *xyram;
	void __iomem *pram;
	void __iomem *dsp_regs;
};

static inline void elcore50_buf_cpy(struct cluster_priv *drv_priv,
				    void __iomem *dst, void *src, size_t size)
{
	memcpy_toio(dst, src, size);
}

static inline u32 elcore50_read(struct elcore50_core *core,
				unsigned int const reg)
{
	u32 value = ioread32(core->dsp_regs + reg);

	dev_dbg(core->dev, "rd reg 0x%08x val 0x%08x\n",
		(unsigned int) reg, value);
	return value;
}

static inline u64 elcore50_read64(struct elcore50_core *core,
				  unsigned int const reg)
{
	u64 value;

	value = readq(core->dsp_regs + reg);

	dev_dbg(core->dev, "rd reg 0x%0x val 0x%016llx\n",
		(unsigned int) reg, value);
	return value;
}

static inline void elcore50_write(u32 const value, struct elcore50_core *core,
				  unsigned int const reg)
{
	dev_dbg(core->dev, "wr reg 0x%08x val 0x%x\n",
		(unsigned int) reg, value);
	iowrite32(value, core->dsp_regs + reg);
}

static inline u32 cluster_read(struct cluster_priv *drv_priv,
			       unsigned int const reg)
{
	u32 value = ioread32(reg + drv_priv->regs);

	dev_dbg(drv_priv->dev, "rdq reg 0x%08x val 0x%08x\n",
		(unsigned int) reg, value);
	return value;
}

#define elcore50_pollreg(core, addr, val, cond, sleep_us) \
({ \
	might_sleep_if(sleep_us); \
	for (;;) { \
		(val) = elcore50_read(core, addr); \
		if (cond) \
			break; \
		if (sleep_us) \
			usleep_range((sleep_us >> 2) + 1, sleep_us); \
	} \
	0; \
})

#define elcore50_pollreg_timeout(core, addr, val, cond, sleep_us, timeout_us) \
({ \
	ktime_t timeout = ktime_add_us(ktime_get(), timeout_us); \
	might_sleep_if(sleep_us); \
	for (;;) { \
		(val) = elcore50_read(core, addr); \
		if (cond) \
			break; \
		if (timeout_us && ktime_compare(ktime_get(), timeout) > 0) { \
			(val) = elcore50_read(core, addr); \
			break; \
		} \
		if (sleep_us) \
			usleep_range((sleep_us >> 2) + 1, sleep_us); \
	} \
	(cond) ? 0 : -ETIMEDOUT; \
})

void elcore50_buf_cpy(struct cluster_priv *drv_priv, void __iomem *dst,
		      void *src, size_t size);
u32 elcore50_read(struct elcore50_core *core, unsigned int const reg);
u64 elcore50_read64(struct elcore50_core *core, unsigned int const reg);
void elcore50_write(u32 const value, struct elcore50_core *core,
		    unsigned int const reg);
u32 cluster_read(struct cluster_priv *drv_priv, unsigned int const reg);
int elcore50_get_core_idx(struct elcore50_core *core, void __user *arg);
int elcore50_get_caps(struct elcore50_core *core, void __user *arg);
void elcore50_core_abort(struct elcore50_core *core);
void print_dump(struct elcore50_core *core);
void elcore50_core_reset(struct elcore50_core *core);
#ifndef ELCORE50_NO_IRQS
irqreturn_t elcore50_irq(int irq, void *priv);
#endif

#endif
