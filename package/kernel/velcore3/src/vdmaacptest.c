// SPDX-License-Identifier: GPL-2.0
/*
 * Module for ACP testing VDMA on MCom-03
 *
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

/*
 *
 * This is the module for coherent port (ACP) testing via VDMA in MCom-03 SoC.
 *
 * The following operations are performed while loading the module:
 *   - allocation two cached buffers (or non-cached if module parameter
 *     nocache=1 is passed);
 *   - filling the first buffer by memset();
 *   - copy the first buffer to XYRAM (SDR DSP local memory) via SDR VDMA;
 *   - copy XYRAM to the second buffer via SDR VDMA;
 *   - comparing the first buffer with the second via memcmp().
 * The last four operations are performed for buffer sizes from 2K to 256K.
 *
 * The list of module parameters are described below in code.
 *
 * This module does not enable coherent port. It should be enabled before
 * starting this module.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <asm/io.h>
#include <asm/cacheflush.h>
#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/timer.h>

#define DMA_BASE		0x19A3000

#define DMA_CHANNEL0		0x0

#define DMA_AdrExt		0x0
#define DMA_AdrInt		0x8
#define DMA_OfsExt		0x10
#define DMA_OfsInt		0x14
#define DMA_RowsCols		0x18
#define DMA_Run			0x1C
#define DMA_Done		0x20
#define DMA_Init		0x24
#define DMA_Irq			0x28
#define DMA_Mask		0x2C
#define DMA_IrqT		0x30
#define DMA_Cfg			0x34
#define DMA_Csr			0x38
#define DMA_AdrTaskL		0x3C
#define DMA_AdrTaskH		0x40

#define AxCACHE			15

#define DIR_RD			0
#define DIR_WR			1

#define PROT			2

#define SIZE			4 // 16 bytes per transfer

#define DMA_CFG ((AxCACHE << 3) | (AxCACHE << 7) | (PROT << 23) | \
			(PROT << 26) | (SIZE << 11))

#define DMA_CFG_RD (DMA_CFG | DIR_RD)
#define DMA_CFG_WR (DMA_CFG | DIR_WR)

#define DMA_CSR_RUN (1 << 0)
#define DMA_CH_STOP ((1 << 8) | (1 << 2))

#define XYRAM_START 0x2E80000

static unsigned int iterations = 1;
module_param(iterations, uint, 0644);
MODULE_PARM_DESC(iterations, "Iterations before stopping test (default: 1)");

static unsigned int pattern = 0xa5;
module_param(pattern, uint, 0644);
MODULE_PARM_DESC(pattern, "Pattern to fill memory");

static unsigned int debug;
module_param(debug, uint, 0644);
MODULE_PARM_DESC(debug, "Enable debug (default: 0)");

static unsigned int nocache;
module_param(nocache, uint, 0644);
MODULE_PARM_DESC(nocache, "Use uncacheable buffers (default: 0)");

static void __iomem *dma_regs;

size_t max_size = 512 * SZ_1K;

static void dump_regs(void)
{
	pr_info("\n\nAE_L: 0x%x\n", readl(dma_regs + DMA_AdrExt));
	pr_info("AE_H: 0x%x\n", readl(dma_regs + DMA_AdrExt + 4));

	pr_info("AI_L: 0x%x\n", readl(dma_regs + DMA_AdrInt));
	pr_info("AI_H: 0x%x\n", readl(dma_regs + DMA_AdrInt + 4));

	pr_info("OfsExt: 0x%x\n", readl(dma_regs + DMA_OfsExt));
	pr_info("OfsInt: 0x%x\n", readl(dma_regs + DMA_OfsInt));
	pr_info("ACNT, BCNT: 0x%x\n", readl(dma_regs + DMA_RowsCols));
	pr_info("Run: 0x%x\n", readl(dma_regs + DMA_Run));
	pr_info("Done: 0x%x\n", readl(dma_regs + DMA_Done));
	pr_info("Init: 0x%x\n", readl(dma_regs + DMA_Init));
	pr_info("Irq: 0x%x\n", readl(dma_regs + DMA_Irq));
	pr_info("Mask: 0x%x\n", readl(dma_regs + DMA_Mask));
	pr_info("IrqT: 0x%x\n", readl(dma_regs + DMA_IrqT));
	pr_info("Cfg: 0x%x\n", readl(dma_regs + DMA_Cfg));
	pr_info("Csr: 0x%x\n", readl(dma_regs + DMA_Csr));
	pr_info("A_INIT_L: 0x%x\n", readl(dma_regs + DMA_AdrTaskL));
	pr_info("A_INIT_H: 0x%x\n\n", readl(dma_regs + DMA_AdrTaskH));
}

static void dma_prepare(void)
{
	writel(0, dma_regs + DMA_Mask);
	writel(0, dma_regs + DMA_Run);
	while (readl(dma_regs + DMA_Run))
		continue;
	writel(0, dma_regs + DMA_Done);
	while (readl(dma_regs + DMA_Done))
		continue;
	writel(0, dma_regs + DMA_Irq);
	writel(0, dma_regs + DMA_OfsExt);
	writel(0, dma_regs + DMA_OfsInt);
	writel(0, dma_regs + DMA_AdrTaskH);
	writel(0, dma_regs + DMA_AdrTaskL);

	writel(0, dma_regs + DMA_Csr);
}

static void dmacpy(dma_addr_t xyram_addr, dma_addr_t ddr_addr, u32 cfg,
		   u32 size)
{
	u16 rows;

	writel(cfg, dma_regs + DMA_Cfg);
	writel(ddr_addr, dma_regs + DMA_AdrExt);
	writel(xyram_addr, dma_regs + DMA_AdrInt);

	rows = size / 64 - 1;
	writel(3 + (rows << 16), dma_regs + DMA_RowsCols);

	writel(DMA_CSR_RUN, dma_regs + DMA_Csr);

	writel(0, dma_regs + DMA_Mask);
	while (readl(dma_regs + DMA_Csr) & DMA_CH_STOP)
		continue;
	while (!readl(dma_regs + DMA_Done))
		continue;
	writel(1, dma_regs + DMA_Irq);
}

static void dump_mem(void *src, void *dst, int size)
{
	int i;

	for (i = 0; i < size / 4; i++)
		pr_info("0x%x : 0x%x\n", readl(src + i * 4),
			readl(dst + i * 4));
}

static void *allocate_buf(struct device *dev, dma_addr_t *dma)
{
	void *buf;

	if (nocache) {
		buf = dma_alloc_coherent(dev, max_size, dma, GFP_KERNEL);
	} else {
		buf = kzalloc(max_size, GFP_KERNEL);
		/* FIXME: Physical address does not equal dma address in some
		 * cases, for example external IOMMU.
		 */
		*dma = virt_to_phys(buf);
	}

	return buf;
}

static void free_buf(struct device *dev, void *buf, dma_addr_t dma)
{
	if (nocache)
		dma_free_coherent(dev, max_size, buf, dma);
	else
		kfree(buf);
}

static int vdmaacptest_probe(struct platform_device *pdev)
{
	void *src, *dst;
	dma_addr_t dmasrc, dmadst;
	ktime_t ktime0, ktime1, ktime2, ktime3, ktime4;
	s64 runtime_memset = 0, runtime_dmacpytoxyram = 0;
	s64 runtime_dmacpytoddr = 0, runtime_memcmp = 0, runtime_total = 0;
	int rc = 0, i;
	size_t size;

#ifndef ELCORE50_MCOM03
	// ACP is available only on MCom-03
	pr_err("ACP is available only on MCom-03");
	return -EPERM;
#endif

	src = allocate_buf(&pdev->dev, &dmasrc);
	if (!src) {
		pr_err("Failed to allocate source buffer\n");
		return -ENOMEM;
	}

	dst = allocate_buf(&pdev->dev, &dmadst);
	if (!dst) {
		pr_err("Failed to allocate destination buffer\n");
		rc = -ENOMEM;
		goto err1;
	}

	if (debug)
		pr_info("dmasrc: 0x%llx, xyram: 0x%x\n, dmadst: 0x%llx\n",
			dmasrc, XYRAM_START, dmadst);

	dma_regs = ioremap(DMA_BASE, SZ_4K);
	if (!dma_regs) {
		pr_err("Failed to remap DMA regs\n");
		rc = -EIO;
		goto err2;
	}

	size = SZ_2K;
	pr_info("size\t\tmemset\t\tcpytoxyram\t\tcpyfromxyram\t\tmemcmp\t\ttotal\n");
	while (size <= SZ_512K) {
		dma_prepare();
		for (i = 0; i < iterations; i++) {
			// Filling src_buf by pattern
			ktime0 = ktime_get();
			memset(src, pattern, size);
			ktime1 = ktime_get();
			// Copy src_buf to XYRAM
			dmacpy(XYRAM_START, dmasrc, DMA_CFG_RD, size);
			ktime2 = ktime_get();
			// Copy XYRAM to dst_buf
			dmacpy(XYRAM_START, dmadst, DMA_CFG_WR, size);
			ktime3 = ktime_get();
			// Compare buffers
			rc |= memcmp(src, dst, size);
			ktime4 = ktime_get();

			runtime_memset += ktime_us_delta(ktime1, ktime0);
			runtime_dmacpytoxyram += ktime_us_delta(ktime2, ktime1);
			runtime_dmacpytoddr += ktime_us_delta(ktime3, ktime2);
			runtime_memcmp += ktime_us_delta(ktime4, ktime3);
		}

		if (rc) {
			pr_info("failed\n");
			dump_mem(src, dst, size);
			goto err3;
		}

		runtime_total = runtime_memset + runtime_dmacpytoxyram +
					runtime_dmacpytoddr + runtime_memcmp;

		pr_info("%zu\t\t%llu\t\t\t%llu\t\t\t%llu\t\t%llu\t\t%llu\n",
			size, runtime_memset, runtime_dmacpytoxyram,
			runtime_dmacpytoddr, runtime_memcmp, runtime_total);

		size *= 2;
		runtime_memset = 0;
		runtime_dmacpytoxyram = 0;
		runtime_dmacpytoddr = 0;
		runtime_memcmp = 0;
		runtime_total = 0;
		rc = 0;
	}

	pr_info("passed\n");
err3:
	if (debug)
		dump_regs();

	iounmap(dma_regs);
err2:
	free_buf(&pdev->dev, dst, dmadst);
err1:
	free_buf(&pdev->dev, src, dmasrc);
	return rc;
}

static int vdmaacptest_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id vdmaacptest_dt_ids[] = {
	{ .compatible = "elvees,acptest" },
	{ /* Sentinel */ }
};
MODULE_DEVICE_TABLE(of, vdmaacptest_dt_ids);

static struct platform_driver vdmaacptest_driver = {
	.probe = vdmaacptest_probe,
	.remove = vdmaacptest_remove,
	.driver = {
		.name = "vdmaacptest",
		.of_match_table = vdmaacptest_dt_ids,
	}
};

module_platform_driver(vdmaacptest_driver);

MODULE_DESCRIPTION("Module for ACP testing on MCom-03");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
