// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#include <linux/uaccess.h>

#include "elcore50-core.h"
#include "elcore50-syscall.h"

int elcore50_get_core_idx(struct elcore50_core *core, void __user *arg)
{
	u32 regval;
	struct elcore50_device_info device_info;
	int ret;

	regval = elcore50_read(core, DSP_IDR);

	device_info.nclusters = IDR_NCLUSTERS(regval);
	device_info.cluster_id = IDR_CLUSTER(regval);
	device_info.cluster_cap = IDR_CLUSTERCAP(regval);
	device_info.core_in_cluster_id = IDR_CORENUM(regval);

	ret = copy_to_user(arg, &device_info,
			   sizeof(struct elcore50_device_info));
	if (ret)
		return ret;

	return 0;
}

int elcore50_get_caps(struct elcore50_core *core, void __user *arg)
{
	struct elcore_caps elcore_caps;
	int ret;

	strcpy(elcore_caps.drvname, "elcore50");
	elcore_caps.hw_id = elcore50_read(core, DSP_IDR);
	elcore_caps.hw_id &= (IDR_VER_MASK | IDR_REV_MASK);
	elcore_caps.hw_id = elcore_caps.hw_id >> IDR_REV_OFFT;

	ret = copy_to_user(arg, &elcore_caps, sizeof(struct elcore_caps));
	if (ret)
		return ret;

	return 0;
}

void elcore50_core_abort(struct elcore50_core *core)
{
	/* switch off device interrupts and force-stop it */
#ifndef ELCORE50_NO_IRQS
	elcore50_write(0, core, DSP_DMASKR);
#endif
	elcore50_write(DCSR_STOP, core, DSP_DCSR);
}

void print_dump(struct elcore50_core *core)
{
	u32 reg_addr, i, j;
	u64 tmp[32];

	if (reg_dump_enable == 0)
		return;

	/* RF */
	reg_addr = DSP_R0;
	for (i = 0; i < 32; i += 4) {
		dev_warn(core->dev, "RF%02d:      %016llx %016llx %016llx %016llx\n",
			 i, elcore50_read64(core, reg_addr + 8 * i),
			 elcore50_read64(core, reg_addr + 8 * (i + 1)),
			 elcore50_read64(core, reg_addr + 8 * (i + 2)),
			 elcore50_read64(core, reg_addr + 8 * (i + 3)));
	}

	/* PCU0 */
	dev_warn(core->dev, "DCSR:      %08x IDR:     %08x\n",
		 elcore50_read(core, DSP_DCSR), elcore50_read(core, DSP_IDR));

	/* PCU2 */
	dev_warn(core->dev, "PC:        %08x IVAR:   %08x IRTAR:   %08x EVAR: %08x\n",
		 elcore50_read(core, DSP_PC), elcore50_read(core, DSP_IVAR),
		 elcore50_read(core, DSP_IRTAR),
		 elcore50_read(core, DSP_EVAR));
	dev_warn(core->dev, "ERTAR:     %08x DVAR:    %08x DRTAR:  %08x\n",
		 elcore50_read(core, DSP_ERTAR), elcore50_read(core, DSP_DVAR),
		 elcore50_read(core, DSP_DRTAR));


	/* PCU1 */
	dev_warn(core->dev, "TMR:       %016llx TMRC:  %016llx\n",
		 elcore50_read64(core, DSP_TMR),
		 elcore50_read64(core, DSP_TMRC));
	dev_warn(core->dev, "TCNTR:     %016llx ICNTR: %016llx CCNTR: %016llx\n",
		 elcore50_read64(core, DSP_TIC_CNTR),
		 elcore50_read64(core, DSP_INSTR_CNTR),
		 elcore50_read64(core, DSP_CMD_CNTR));

	/* PCU3 */
	reg_addr = DSP_P0;
	dev_warn(core->dev, "P0:        %08x %08x %08x %08x\n",
		 elcore50_read(core, reg_addr),
		 elcore50_read(core, reg_addr + 4),
		 elcore50_read(core, reg_addr + 8),
		 elcore50_read(core, reg_addr + 12));
	dev_warn(core->dev, "P4:        %08x %08x %08x %08x\n",
		 elcore50_read(core, reg_addr + 16),
		 elcore50_read(core, reg_addr + 20),
		 elcore50_read(core, reg_addr + 24),
		 elcore50_read(core, reg_addr + 28));

	reg_addr = DSP_VP0;
	dev_warn(core->dev, "VP0:       %016llx %016llx %016llx %016llx\n",
		 elcore50_read64(core, reg_addr),
		 elcore50_read64(core, reg_addr + 8),
		 elcore50_read64(core, reg_addr + 16),
		 elcore50_read64(core, reg_addr + 24));
	dev_warn(core->dev, "VP4:       %016llx %016llx %016llx %016llx\n",
		 elcore50_read64(core, reg_addr + 32),
		 elcore50_read64(core, reg_addr + 40),
		 elcore50_read64(core, reg_addr + 48),
		 elcore50_read64(core, reg_addr + 56));

	/* PCU4 */
	dev_warn(core->dev, "CSP:       %08x\n", elcore50_read(core, DSP_CSP));
	dev_warn(core->dev, "LC0:       %08x %08x %08x %08x\n",
		elcore50_read(core, DSP_LC0), elcore50_read(core, DSP_LC1),
		elcore50_read(core, DSP_LC2), elcore50_read(core, DSP_LC3));
	dev_warn(core->dev, "LB0:       %08x %08x %08x %08x\n",
		elcore50_read(core, DSP_LB0), elcore50_read(core, DSP_LB1),
		elcore50_read(core, DSP_LB2), elcore50_read(core, DSP_LB3));
	dev_warn(core->dev, "LA0:       %08x %08x %08x %08x\n",
		elcore50_read(core, DSP_LA0), elcore50_read(core, DSP_LA1),
		elcore50_read(core, DSP_LA2), elcore50_read(core, DSP_LA3));

	/* PCU6 */
	dev_warn(core->dev, "IRQ_INDEX: %08x IRQR:  %08x IMASKR: %08x DQSTR: %08x\n",
		 elcore50_read(core, DSP_IRQ_INDEX),
		 elcore50_read(core, DSP_IRQR),
		 elcore50_read(core, DSP_IMASKR),
		 elcore50_read(core, DSP_DQSTR));
	dev_warn(core->dev, "DMASKR:    %08x INDEX: %08x UIPC:   %08x\n",
		 elcore50_read(core, DSP_DMASKR),
		 elcore50_read(core, DBG_INDEX),
		 elcore50_read(core, DSP_UIPC));
	dev_warn(core->dev, "BAPC:      %016llx\n",
		 elcore50_read64(core, DSP_BAPC));

	/* PCU10 */
	dev_warn(core->dev, "M0:        %08x %08x\n",
		 elcore50_read(core, DSP_M0), elcore50_read(core, DSP_M1));

	/* PCU12 */
	dev_warn(core->dev, "CTRL:      %08x INVCTRL:  %08x INVADDR:  %08x\n",
		 elcore50_read(core, DSP_CTRL),
		 elcore50_read(core, DSP_INVCTRL),
		 elcore50_read(core, DSP_INVADDR));
	dev_warn(core->dev, "ASID:      %08x CREGIONS: %08x MREGIONS: %08x\n",
		 elcore50_read(core, DSP_ASID),
		 elcore50_read(core, DSP_CREGIONS),
		 elcore50_read(core, DSP_MREGIONS));
	dev_warn(core->dev, "SWAITREG0: %08x SWAITREG1: %08x VWAITREG0: %08x VWAITREG1: %08x\n",
		 elcore50_read(core, DSP_SWAITREG0),
		 elcore50_read(core, DSP_SWAITREG1),
		 elcore50_read(core, DSP_VWAITREG0),
		 elcore50_read(core, DSP_VWAITREG1));

	/* Caches */
	dev_warn(core->dev, "L0DC_CTRL: %08x L1IC_CTRL: %08x L1DC_CTRL: %08x L2_CTRL:   %08x\n",
		 elcore50_read(core, L0DC_CTRL),
		 elcore50_read(core, L1IC_CTRL),
		 elcore50_read(core, L1DC_CTRL), elcore50_read(core, L2_CTRL));

	/* VF */
	for (i = 0, reg_addr = DSP_VF_START; i < 64; ++i, reg_addr += 0x40) {
		for (j = 0; j < 8; ++j)
			tmp[j] = elcore50_read64(core, reg_addr + j * 8);
		dev_warn(core->dev, "VF%02dH:     %016llx %016llx %016llx %016llx\n",
			 i, tmp[7], tmp[6], tmp[5], tmp[4]);
		dev_warn(core->dev, "VF%02dL:     %016llx %016llx %016llx %016llx\n",
			 i, tmp[3], tmp[2], tmp[1], tmp[0]);
	}

	/* VMMU */
	dev_warn(core->dev, "PTW_PBA_L: %08x PTW_PBA_H: %08x\n",
		 elcore50_read(core, VMMU_PTW_PBA_L),
		 elcore50_read(core, VMMU_PTW_PBA_H));
	dev_warn(core->dev, "PTW_CFG:   %08x TLB_CTRL:  %08x\n",
		 elcore50_read(core, VMMU_PTW_CFG),
		 elcore50_read(core, VMMU_TLB_CTRL));

	dev_warn(core->dev, "TLBXCPT:   NUM ADDR     TYPE\n");
	for (i = 0; i < VMMU_TLBS; ++i) {
		elcore50_write(i, core, VMMU_TLBXCPT_NUM);
		dev_warn(core->dev, "           %d   %08x %d\n",
			 elcore50_read(core, VMMU_TLBXCPT_NUM),
			 elcore50_read(core, VMMU_TLBXCPT_ADDR),
			 elcore50_read(core, VMMU_TLBXCPT_TYPE));
	}
}

void elcore50_core_reset(struct elcore50_core *core)
{
	do {
		elcore50_write(DCSR_RESET, core, DSP_DCSR);
	} while (elcore50_read(core, DSP_MBARREG) != 0);
}

#ifndef ELCORE50_NO_IRQS
irqreturn_t elcore50_irq(int irq, void *priv)
{
	struct elcore50_core *core = (struct elcore50_core *) priv;
	struct elcore50_job_inst_desc *desc;
	unsigned long flags;
	int empty;

	spin_lock_irqsave(&core->queue_lock, flags);
	desc = list_first_entry(&core->job_queue,
				struct elcore50_job_inst_desc,
				queue_node);
	empty = list_empty(&core->job_queue);
	spin_unlock_irqrestore(&core->queue_lock, flags);

	elcore50_write(0, core, DSP_DMASKR);

	if (empty) {
		dev_err(core->dev, "IRQ received, but no jobs in queue!\n");
		return IRQ_NONE;
	}

	desc->core_stopped = 1;

	wake_up(&desc->irq_waitq);
	return IRQ_HANDLED;
}
#endif
