// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2018-2020 RnD Center "ELVEES", JSC
 */

#include <linux/debugfs.h>
#include <linux/idr.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>

#include "elcore50-job-instance.h"
#include "elcore50-debug.h"
#include "elcore50-syscall.h"
#include "elcore50-reset.h"

static struct class *elcore50_class;

static struct dentry *pdentry;

static struct idr elcore50_idr;
static spinlock_t elcore50_idr_lock;

int mod_caches = 3;
int mod_dbg_registers;

u32 irq_timeout_msec;
u32 reg_dump_enable;

module_param_named(caches, mod_caches, int, 0);
module_param_named(dbg_registers_simple, mod_dbg_registers, int, 0);

/* RUNTIME POWER MANAGEMENT FUNCTIONS */

static int elcore50_runtime_suspend(struct device *dev)
{
	struct cluster_priv *drv_priv = dev_get_drvdata(dev);
	int i;

	for (i = 0; i < drv_priv->clock_count; ++i)
		clk_disable(drv_priv->clocks[i]);

	return 0;
}

static int elcore50_runtime_resume(struct device *dev)
{
	struct cluster_priv *drv_priv = dev_get_drvdata(dev);
	int ret, i;

	for (i = 0; i < drv_priv->clock_count; ++i) {
		ret = clk_enable(drv_priv->clocks[i]);
		if (ret < 0) {
			dev_err(dev, "could not enable %d clock\n", i);
			goto err_suspend;
		}
	}
	return 0;
err_suspend:
	while (i >= 0)
		clk_disable(drv_priv->clocks[--i]);

	return ret;
}

/* END POWER MANAGEMENT FUNCTIONS */

/* FILE FUNCTIONS */

static int elcore50_open(struct inode *inode, struct file *file)
{
	struct elcore50_core *core;
	int ret;

	core = container_of(inode->i_cdev, struct elcore50_core, cdev);

	file->private_data = core;

	ret = pm_runtime_get_sync(core->drv_priv->dev);

	return ret < 0 ? ret : 0;
}

static long elcore50_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct elcore50_core *pdata =
		(struct elcore50_core *)file->private_data;
	void __user *const uptr = (void __user *)arg;

	switch (cmd) {
	case ELCORE50_IOC_CREATE_JOB:
		return elcore50_create_job(file, uptr);
	case ELCORE50_IOC_ENQUEUE_JOB:
		return elcore50_enqueue_job_inst(pdata, uptr);
	case ELCORE50_IOC_GET_JOB_STATUS:
		return elcore50_get_job_inst_status(pdata, uptr);
	case ELCORE50_IOC_GET_JOB_COUNT:
		return elcore50_get_job_inst_count(pdata, uptr);
	case ELCORE50_IOC_GET_JOB_LIST:
		return elcore50_get_job_inst_list(pdata, uptr);
	case ELCORE50_IOC_DBG_JOB_ATTACH:
		return elcore50_job_dbg_attach(pdata, uptr);
	case ELCORE50_IOC_GET_CORE_IDX:
		return elcore50_get_core_idx(pdata, uptr);
	case ELCORE50_IOC_CREATE_MAPPER:
		return elcore50_create_mapper(pdata, uptr);
	case ELCORE50_IOC_CREATE_BUFFER:
		return elcore50_create_buffer(pdata, uptr);
	case ELCORE50_IOC_SYNC_BUFFER:
		return elcore50_sync_buffer(pdata, uptr);
	case ELCIOC_GET_CAPS:
		return elcore50_get_caps(pdata, uptr);
	}
	return -ENOTTY;
}

static int elcore50_release(struct inode *inode, struct file *file)
{
	struct elcore50_core *core;

	core = container_of(inode->i_cdev, struct elcore50_core, cdev);

	pm_runtime_put(core->drv_priv->dev);

	return 0;
}

static const struct file_operations elcore50_fops = {
	.owner = THIS_MODULE,
	.open = elcore50_open,
	.unlocked_ioctl = elcore50_ioctl,
	.release = elcore50_release,
};

/* END FILE FUNCTIONS */

/* PROBE/INIT/DESTROY */

static int elcore50_core_init(struct elcore50_core *core,
			      struct cluster_priv *drv_priv,
			      unsigned int major, unsigned int minor,
			      int corenum)
{
	struct device *dev;
	int ret;

	core->drv_priv = drv_priv;
	cdev_init(&core->cdev, &elcore50_fops);
	ret = cdev_add(&core->cdev, MKDEV(major, minor), 1);
	if (ret < 0) {
		dev_err(drv_priv->dev, "Failed to add ELcore-50 cdev\n");
		goto err_none;
	}
	idr_preload(GFP_KERNEL);
	spin_lock(&elcore50_idr_lock);

	core->cdev_idr = idr_alloc(&elcore50_idr, core, 0, ~0, GFP_KERNEL);

	spin_unlock(&elcore50_idr_lock);
	idr_preload_end();
	if (core->cdev_idr < 0)  {
		dev_err(drv_priv->dev, "Failed to allocate ELcore-50 cdev\n");
		goto err_none;
	}
	dev = device_create(elcore50_class, drv_priv->dev,
				MKDEV(major, minor),
				NULL, "elcore%d", core->cdev_idr);
	if (IS_ERR(dev)) {
		/* this way we can be assured cores[i] is deallocated */
		dev_err(drv_priv->dev, "Failed to create ELcore-50 device\n");
		ret = PTR_ERR(dev);
		goto err_cdev;
	}
	core->dev = dev;
	core->corenum = corenum;
#ifdef ELCORE50_MCOM03
	core->xyram = drv_priv->mem;
	core->dsp_regs = drv_priv->regs;
#else
	core->xyram = drv_priv->mem + SZ_2M * corenum;
	core->dsp_regs = drv_priv->regs + DSPNEXT_OFF * corenum;
#endif
	core->pram = core->xyram + SZ_1M;

	INIT_LIST_HEAD(&core->job_queue);
	spin_lock_init(&core->queue_lock);
	core->work_q = alloc_ordered_workqueue("elcore-wq%i", 0,
					       core->cdev_idr);
	if (!core->work_q) {
		dev_err(core->dev, "Failed to allocate workqueue\n");
		ret = -ENOMEM;
		goto err_device;
	}
	return 0;
err_device:
	device_destroy(elcore50_class, MKDEV(major, minor));
err_cdev:
	cdev_del(&core->cdev);
err_none:
	if (core->cdev_idr)
		idr_remove(&elcore50_idr, core->cdev_idr);
	return ret;
}

static void elcore50_core_destroy(struct elcore50_core *core,
				  struct cluster_priv *drv_priv)
{
	struct elcore50_job_inst_desc *cursor, *store;

	list_for_each_entry_safe(cursor, store, &core->job_queue, queue_node) {
		elcore50_cancel_job_inst(cursor);
	}
	destroy_workqueue(core->work_q);
	device_destroy(elcore50_class, core->cdev.dev);
	cdev_del(&core->cdev);
	idr_remove(&elcore50_idr, core->cdev_idr);
}

static int elcore50_cores_init(struct cluster_priv *drv_priv, int ncores)
{
	int ret, major, minor, i;

	ret = alloc_chrdev_region(&drv_priv->dev_num, 0, ncores, "elcore50");
	if (ret < 0) {
		dev_err(drv_priv->dev, "Failed to allocate chrdev region\n");
		return ret;
	}

	drv_priv->ncores = ncores;
	drv_priv->cores = devm_kcalloc(drv_priv->dev,
				       ncores, sizeof(struct elcore50_core),
				       GFP_KERNEL);

	major = MAJOR(drv_priv->dev_num);
	for (i = 0; i < ncores; i++) {
		minor = MINOR(drv_priv->dev_num) + i;
		ret = elcore50_core_init(&drv_priv->cores[i],
					 drv_priv, major, minor, i);
		if (ret) {
			dev_err(drv_priv->dev, "Failed to initialize core %d\n",
				i);
			goto err_dev;
		}
	}
	return 0;
err_dev:
	while (i > 0) {
		i--;
		elcore50_core_destroy(&drv_priv->cores[i], drv_priv);
	}
	unregister_chrdev_region(drv_priv->dev_num, ncores);
	return ret;
}

#ifndef ELCORE50_NO_IRQS
static void elcore50_free_irqs(struct cluster_priv *drv_priv)
{
	int i, irq;

	for (i = 0; i < drv_priv->ncores; i++) {
		for (irq = 0; irq < drv_priv->nirqs; ++irq) {
			if (drv_priv->irqs[i * drv_priv->nirqs + irq] == 0)
				break;
			devm_free_irq(drv_priv->dev,
				drv_priv->irqs[i * drv_priv->nirqs + irq],
				&drv_priv->cores[i]);
		}
	}
	devm_kfree(drv_priv->dev, drv_priv->irqs);
}
#endif

static void elcore50_cores_destroy(struct cluster_priv *drv_priv)
{
	int i;

#ifndef ELCORE50_NO_IRQS
	elcore50_free_irqs(drv_priv);
#endif
	for (i = 0; i < drv_priv->ncores; i++)
		elcore50_core_destroy(&drv_priv->cores[i], drv_priv);
	unregister_chrdev_region(drv_priv->dev_num, drv_priv->ncores);
}

static int elcore50_clock_init(struct cluster_priv *drv_priv)
{
	struct device_node *np = drv_priv->dev->of_node;
	int i, ret;

	drv_priv->clock_count = of_clk_get_parent_count(np);
	if (!drv_priv->clock_count)
		return 0;

	drv_priv->clocks = devm_kcalloc(drv_priv->dev, drv_priv->clock_count,
					sizeof(struct clk *), GFP_KERNEL);
	if (!drv_priv->clocks)
		return -ENOMEM;

	for (i = 0; i < drv_priv->clock_count; ++i) {
		drv_priv->clocks[i] = of_clk_get(np, i);
		if (drv_priv->clocks[i]) {
			ret = clk_prepare_enable(drv_priv->clocks[i]);
			if (ret) {
				dev_err(drv_priv->dev, "clock %d error: %ld\n",
					i, PTR_ERR(drv_priv->clocks[i]));
				clk_put(drv_priv->clocks[i]);
				drv_priv->clocks[i] = NULL;
				return ret;
			}
		}
	}

	return 0;
}

static void elcore50_clock_destroy(struct cluster_priv *drv_priv)
{
	int i;

	if (!drv_priv->clocks)
		return;

	for (i = 0; i < drv_priv->clock_count; ++i) {
		if (drv_priv->clocks[i]) {
			clk_unprepare(drv_priv->clocks[i]);
			clk_put(drv_priv->clocks[i]);
		}
	}

	devm_kfree(drv_priv->dev, drv_priv->clocks);
}

static int elcore50_probe(struct platform_device *pdev)
{
	struct cluster_priv *drv_priv;
	int ret, ncores;
#ifndef ELCORE50_MCOM03
	uint32_t tmp_read;
#endif
#ifndef ELCORE50_NO_IRQS
	int i;
#endif
	struct resource *res;

	drv_priv = devm_kzalloc(&pdev->dev, sizeof(struct cluster_priv),
				GFP_KERNEL);
	if (!drv_priv)
		return -ENOMEM;
	drv_priv->dev = &pdev->dev;

	ret = elcore50_reset_init(drv_priv);
	if (ret)
		return ret;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get registers\n");
		return -ENOENT;
	}

	ret = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(&pdev->dev, "Failed to set DMAMASK\n");
		return ret;
	}

	drv_priv->regs = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(drv_priv->regs)) {
		dev_err(&pdev->dev, "Failed to map registers: %ld\n",
			PTR_ERR(drv_priv->regs));
		return PTR_ERR(drv_priv->regs);
	}
	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res) {
		dev_err(&pdev->dev, "Failed to get memory\n");
		return -ENOENT;
	}

	drv_priv->mem = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(drv_priv->mem)) {
		dev_err(&pdev->dev, "Failed to map registers\n");
		return PTR_ERR(drv_priv->mem);
	}

	ret = elcore50_clock_init(drv_priv);
	if (ret)
		goto err_clock;

	pm_runtime_set_active(drv_priv->dev);
	pm_runtime_enable(drv_priv->dev);

#ifdef ELCORE50_MCOM03
	ncores = 1;
#else
	tmp_read = ioread32(drv_priv->regs + DSP_IDR);
	ncores = (tmp_read & IDR_COCNT_MASK) >> IDR_COCNT_OFFT;
	WARN_ON((tmp_read & IDR_VER_MASK) >> IDR_VER_OFFT != 0x32);
	WARN_ON((tmp_read & IDR_REV_MASK) >> IDR_REV_OFFT != 0x66);
#endif
	ret = elcore50_cores_init(drv_priv, ncores);
	if (ret)
		return ret;
#ifndef ELCORE50_NO_IRQS
	drv_priv->nirqs = of_property_count_elems_of_size(
				drv_priv->dev->of_node,
				"interrupts", sizeof(int));
	drv_priv->irqs = devm_kcalloc(&pdev->dev, drv_priv->nirqs,
				      sizeof(unsigned int),
				      GFP_KERNEL | __GFP_ZERO);
	if (!drv_priv->irqs) {
		ret = -ENOMEM;
		goto err_device;
	}
	drv_priv->nirqs /= ncores;
	for (i = 0; i < drv_priv->nirqs * ncores; i++) {
		drv_priv->irqs[i] = platform_get_irq(pdev, i);
		if (drv_priv->irqs[i] < 0) {
			dev_err(&pdev->dev,
				"Failed to get interrupt\n");
			ret = drv_priv->irqs[i];
			goto err_irq;
		}
		ret = devm_request_irq(&pdev->dev, drv_priv->irqs[i],
				       elcore50_irq, IRQF_SHARED,
				       "elcore50",
				       &drv_priv->cores[i / drv_priv->nirqs]);

		if (ret) {
			dev_err(&pdev->dev,
				"Failed to get interrupt resource\n");
			ret = -EINVAL;
			goto err_irq;
		}
	}
#endif
	platform_set_drvdata(pdev, drv_priv);

	pm_runtime_suspend(drv_priv->dev);

	dev_info(drv_priv->dev, "%d ELcore-50 cores initialized at %px\n",
		 ncores, drv_priv);
	return 0;
#ifndef ELCORE50_NO_IRQS
err_irq:
	elcore50_free_irqs(drv_priv);
err_device:
	elcore50_cores_destroy(drv_priv);
#endif
err_clock:
	pm_runtime_disable(drv_priv->dev);
	elcore50_clock_destroy(drv_priv);
	elcore50_reset_fini(drv_priv);
	dev_err(drv_priv->dev, "elcore50 init failed, error %d\n", ret);
	return ret;
}

static int elcore50_remove(struct platform_device *pdev)
{
	struct cluster_priv *drv_priv = platform_get_drvdata(pdev);

	elcore50_cores_destroy(drv_priv);
	elcore50_reset_fini(drv_priv);
	pm_runtime_disable(drv_priv->dev);
	elcore50_clock_destroy(drv_priv);
	return 0;
}

static const struct dev_pm_ops elcore50_pm_ops = {
	SET_RUNTIME_PM_OPS(elcore50_runtime_suspend,
			   elcore50_runtime_resume,
			   NULL)
};

#ifdef CONFIG_OF
static const struct of_device_id elcore50_dt_ids[] = {
	{ .compatible = "elvees,elcore50" },
	{}
};
MODULE_DEVICE_TABLE(of, elcore50_dt_ids);
#endif

static struct platform_driver elcore50_driver = {
	.driver = {
		.name = "elcore50",
		.pm = &elcore50_pm_ops,
		.of_match_table = of_match_ptr(elcore50_dt_ids),
	},
	.probe = elcore50_probe,
	.remove = elcore50_remove,
};

static int __init elcore50_init(void)
{
	struct dentry *irq_timeout_dentry, *reg_dump_dentry;

	elcore50_class = class_create(THIS_MODULE, "elcore50");

	pdentry = debugfs_create_dir("elcore50", NULL);
	if (!pdentry)
		return -ENOMEM;

	idr_init(&elcore50_idr);
	spin_lock_init(&elcore50_idr_lock);

	irq_timeout_dentry = debugfs_create_u32("irq-timeout-msec", 0600,
						pdentry, &irq_timeout_msec);
	if (!irq_timeout_dentry) {
		debugfs_remove_recursive(pdentry);
		return -ENOMEM;
	}

	reg_dump_dentry = debugfs_create_u32("reg-dump-enable", 0600, pdentry,
					     &reg_dump_enable);

	return platform_driver_register(&elcore50_driver);
}

static void __exit elcore50_exit(void)
{
	platform_driver_unregister(&elcore50_driver);
	debugfs_remove_recursive(pdentry);
	idr_destroy(&elcore50_idr);
	class_destroy(elcore50_class);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ELVEES ELcore-50 driver");

module_init(elcore50_init);
module_exit(elcore50_exit);
