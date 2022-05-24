/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright 2018-2020 RnD Center "ELVEES", JSC
 */

#ifndef _REGS_H_
#define _REGS_H_

#define DSPNEXT_OFF	0x40000

#define PRAM_OFF	0x100000

#define DSP_R0		0x0
#define DSP_R1		0x8
#define DSP_R2		0x10
#define DSP_R3		0x18
#define DSP_R8		0x40
#define DSP_R12		0x60
#define DSP_R13		0x68
#define DSP_R31		0xF8
#define DSP_RF_NEXT	8
#define DSP_RF_NUM	32
#define DSP_RF_LAST	(DSP_R0 + DSP_RF_NUM * DSP_RF_NEXT)
#define DSP_DCSR	0x200

#define DSP_VF0		0x1000
#define DSP_VF_NEXT	8
#define DSP_VF_NUM	32
#define DSP_VF_LAST	(DSP_VF0 + DSP_VF_NUM * DSP_VF_NEXT)
#define DSP_VAC0	0x2000
#define DSP_VAC_NEXT

#define DCSR_STOP	BIT(3)
#define DCSR_RUN	BIT(14)
#define DCSR_RESET	BIT(15)

#define DSP_IDR		0x208
#define IDR_VER_MASK	GENMASK(31, 24)
#define IDR_VER_OFFT	24
#define IDR_REV_MASK	GENMASK(23, 16)
#define IDR_REV_OFFT	16
#define IDR_CLCNT_MASK	GENMASK(15, 12)
#define IDR_CLCNT_OFFT	12
#define IDR_COCNT_MASK	GENMASK(11, 8)
#define IDR_COCNT_OFFT	8
#define IDR_CLNUM_MASK	GENMASK(7, 4)
#define IDR_CLNUM_OFFT	4
#define IDR_CONUM_MASK	GENMASK(3, 0)
#define IDR_CONUM_OFFT	0
#define IDR_NCLUSTERS(x)	(((x) & IDR_CLCNT_MASK) >> IDR_CLCNT_OFFT)
#define IDR_CLUSTER(x)		(((x) & IDR_CLNUM_MASK) >> IDR_CLNUM_OFFT)
#define IDR_CLUSTERCAP(x)	(((x) & IDR_COCNT_MASK) >> IDR_COCNT_OFFT)
#define IDR_CORENUM(x)		(((x) & IDR_CONUM_MASK) >> IDR_CONUM_OFFT)

#define DSP_TMR		0x280
#define DSP_TMRC	0x288
#define DSP_TIC_CNTR	0x290
#define DSP_INSTR_CNTR	0x298
#define DSP_CMD_CNTR	0x2A0

#define DSP_PC		0x300
#define DSP_IVAR	0x310
#define DSP_IRTAR	0x318
#define DSP_EVAR	0x320
#define DSP_ERTAR	0x328
#define DSP_DVAR	0x330
#define DSP_DRTAR	0x338

#define DSP_P0		0x380
#define DSP_P7		0x39C
#define DSP_VP0		0x3C0
#define DSP_VP7		0x3F8

#define DSP_CSP		0x400
#define DSP_LC0		0x410
#define DSP_LC1		0x414
#define DSP_LC2		0x418
#define DSP_LC3		0x41C
#define DSP_LB0		0x440
#define DSP_LB1		0x448
#define DSP_LB2		0x450
#define DSP_LB3		0x458
#define DSP_LA0		0x460
#define DSP_LA1		0x468
#define DSP_LA2		0x470
#define DSP_LA3		0x478

#define DSP_IRQ_INDEX	0x500
#define DSP_IRQR	0x504
#define DSP_IMASKR	0x508
#define DSP_DQSTR	0x50C
#define DSP_DMASKR	0x510
#define DBG_INDEX	0x514
#define DSP_BAPC	0x518
#define DSP_UIPC	0x520

#define DSP_DBDCSR	0x600
#define DSP_CNTRUN	0x604
#define DSP_DBCNTR	0x608
#define DSP_DBSAR0	0x6C0
#define DSP_DBSAR1	0x6C8
#define DSP_DBSAR2	0x6D0
#define DSP_DBSAR3	0x6D8
#define DSP_DBSARNEXT	8

#define DSP_M0		0x700
#define DSP_M1		0x708

#define IRQR_SC		BIT(2)
#define IRQR_DBG	BIT(3)
#define DQSTR_STP	BIT(31)
#define DQSTR_SC	BIT(2)
#define DQSTR_DBG	BIT(3)
#define DQSTR_ERRS	(GENMASK(5, 0) | GENMASK(19, 7))
#define DBG_ID		GENMASK(3, 0)
#define DBG_ID_DBSAR0	4
#define DBG_ID_DBSAR1	5
#define DBG_ID_DBSAR2	6
#define DBG_ID_DBSAR3	7
#define DBG_ID_DBCNTR	8
#define DBG_ID_DBBREAK	9
#define DBG_ID_QLIC		15
#define DBDCSR_WRE	BIT(31)

#define DSP_IRQ_INDEX_SCN(x)	(((x) >> 24) & 0xFF)

#define DBDCSR_WRE	BIT(31)

#define DSP_CTRL	0x800

#define CTRL_EPROTSP(x)	((x) << 0)
#define CTRL_ASIDINV	BIT(4)
#define CTRL_PRAMEn	(BIT(5) | BIT(9))
#define CTRL_XYEn	(BIT(6) | BIT(7) | BIT(10) | BIT(11))
#define CTRL_EPortEn	(BIT(8) | BIT(12))
#define CTRL_ST_PRED	BIT(13)
#define CTRL_PF		BIT(15)
#define CTRL_PFN(x)	((x) << 16)
#define CTRL_DOPF	BIT(18)
#define CTRL_DOPFN(x)	((x) << 19)
#define CTRL_PFB(x)	((x) << 21)
#define CTRL_VW_RM	BIT(23)
#define CTRL_VR_DM	BIT(24)
#define CTRL_SVISync	BIT(25)
#define CTRL_SVBSync	BIT(26)
#define CTRL_BrCtrlEn	BIT(27)
#define CTRL_MBAR	BIT(28)
#define CTRL_PipelineFlush	BIT(30)
#define CTRL_AddrCheck	BIT(31)

#define DSP_INVCTRL	0x804

#define DSP_INCTRL_INVAL_ALL	0xffaf
#define DSP_INVCTRL_FLUSH_ALL	0xffff

#define DSP_INVADDR	0x808
#define DSP_ASID	0x80C
#define DSP_SWAITREG0	0x81C
#define DSP_SWAITREG1	0x820
#define DSP_VWAITREG0	0x824
#define DSP_VWAITREG1	0x828

#define DSP_MBARREG	0x82C

#define INVCTRL_ALLCAC	0xFF80
#define INVCTRL_L0	(BIT(0) | BIT(2))
#define INVCTRL_L1	(BIT(1) | BIT(3))
#define INVCTRL_L1F	BIT(4)
#define INVCTRL_L2F	BIT(6)

#define DSP_CREGIONS	0x810
#define DSP_MREGIONS	0x814

#define VMMU_PAGE_MAX_LEVEL	3

#define VMMU_PTW_PBA_L		0x24000
#define VMMU_PTW_PBA_H		0x24004
#define VMMU_PTW_CFG		0x24008

// 41 bit address space
#define VMMU_PTW_CFG_41B	(0xA << 1)
#define VMMU_PTW_CFG_INV	BIT(0)
#define VMMU_PTW_CFG_A_CACHE(x)	((x) << 15)
#define VMMU_PTW_CFG_A_PROT(x)	((x) << 19)
#define VMMU_PTW_CFG_PREFETCH	BIT(22)

#define VMMU_TLBXCPT_NUM	0x2400C
#define VMMU_TLBXCPT_ADDR	0x24010
#define VMMU_TLBXCPT_TYPE	0x24014
#define VMMU_MAPSEG_START_L	0x24018
#define VMMU_MAPSEG_START_H	0x2401C
#define VMMU_MAPSEG_END_L	0x24020
#define VMMU_MAPSEG_END_H	0x24024
#define VMMU_MAPSEG_ENABLE	0x24028
#define VMMU_TLB_CTRL		0x24040
#define VMMU_TLBS		4

#define VMMU_TLB_CTRL_DUMMY	(BIT(5) | BIT(6))
#define DQSTR_TLB_ERRS		GENMASK(19, 16)

#define L1DC_CTRL		0x34400

#define L1DC_CTRL_EN		BIT(0)
#define L1DC_CTRL_MBAR		BIT(1)
#define L1DC_CTRL_FLUSH		BIT(3)
#define L1DC_CTRL_CEN		BIT(6)
#define L1DC_CTRL_WRBK		BIT(8)
#define L1DC_CTRL_WRAL		BIT(9)
#define L1DC_CTRL_INVL2		BIT(11)
#define L1DC_CTRL_REFILL(x)	((x) << 12)
#define L1DC_CTRL_PFSN(x)	((x) << 17)
#define L1DC_CTRL_PFVN(x)	((x) << 20)
#define L1DC_CTRL_PFIN(x)	((x) << 23)
#define L1DC_CTRL_PREFETCHERS	GENMASK(17, 25)

#define L1DC_CTRL_PFN_0		0
#define L1DC_CTRL_PFN_1		1
#define L1DC_CTRL_PFN_2		2
#define L1DC_CTRL_PFN_4		3
#define L1DC_CTRL_PFN_8		4
#define L1DC_CTRL_PFN_16	5
#define L1DC_CTRL_PFN_32	6
#define L1DC_CTRL_PFN_64	7
#define L1DC_CTRL_PFB(x)	((x) << 26)
#define L1_CTRL_PFB_UNLIM	0
#define L1_CTRL_PFB_4K		1
#define L1_CTRL_PFB_2M		2
#define L1_CTRL_PFB_1G		3
#define L1DC_CTRL_PFBWEN	BIT(29)

#define L1IC_CTRL		0x2A400

#define L1IC_CTRL_EN		BIT(0)
#define L1IC_CTRL_PF		BIT(2)
#define L1IC_CTRL_L1PFN(x)	((x) << 3)
#define L1IC_CTRL_PFB(x)	((x) << 6)
#define L1IC_CTRL_CEN		BIT(8)


#define L0DC_CTRL		0x36200

#define L0DC_CTRL_L0En		BIT(0)
#define L0DC_CTRL_INV_L0	BIT(1)
#define L0DC_CTRL_L0CNTREn	BIT(2)

#define L2_CTRL			0x37000

#define L2_CTRL_EN		BIT(6)
#define L2_CTRL_AXIPROT(x)	((x) << 10)
#define L2_CTRL_CountersEN	BIT(14)
#define L2_CTRL_WR(x)		((x) << 16)
#define L2_CTRL_CV_OFFT		19
#define L2_CTRL_UCAXICACHE(x)	((x) << 21)
#define L2_CTRL_INVF		BIT(29)
#define L2_CTRL_CLR		BIT(31)

#define DSP_VF_START		0x1000

#define QCTR_DIV_DSP0S          0x000
#define QCTR_DIV_DSP1S          0x004
#define QCTR_DIV_DSP2S          0x008
#define QCTR_DIV_DSP3S          0x00c
#define QCTR_DIV_VCPU           0x020
#define QCTR_DIV_SYSTEM         0x024
#define QCTR_DIV_NOC            0x028
#define QCTR_DIV_NOCREG         0x02c
#define QCTR_DIV_TRACE          0x030
#define QCTR_GATE_DSP0IF        0x034
#define QCTR_GATE_DSP1IF        0x038
#define QCTR_GATE_DSP2IF        0x03c
#define QCTR_GATE_DSP3IF        0x040
#define QCTR_SWRST_DSP0         0x048
#define QCTR_SWRST_DSP1         0x04c

#define QCTR_SWRST_DSP2         0x050
#define QCTR_SWRST_DSP3         0x054
#define QCTR_SWRST_VCPU         0x05c
#define QCTR_SWRST_FLAGS        0x060
#define QCTR_GATE_QUELCORE      0x064
#define QCTR_TFUNNEL_CTR        0x130
#define QCTR_TFUNNEL_PRIOR      0x134
#define QCTR_STRAP              0x138
#define QCTR_CONFIG             0x13c
#define QCTR_SOFT_NMI_SET       0x140
#define QCTR_SOFT_NMI_CLEAR     0x144
#define QCTR_SOFT_NMI_MASK      0x148
#define QCTR_SOFT_NMI_STATUS    0x14c
#define QCTR_CSR_DSP            0x150

#define INTERNAL_DSP_INTERLEAVE	BIT(19)
#ifdef ELCORE50_MCOM03
#define PHYS_INTERNAL_DSP		0x2E00000
#else
#define PHYS_INTERNAL_DSP		0x10000000
#endif
#define PHYS_INTERNAL_INTERLEAVE_DSP	(PHYS_INTERNAL_DSP | \
						INTERNAL_DSP_INTERLEAVE)
#define INTERNAL_DSP_SIZE	SZ_512K
#define INTERNAL_DSP_INTERLEAVE	BIT(19)
#ifdef ELCORE50_MCOM03
#define PHYS_INTERNAL_PRAM_DSP	0x2F00000
#define PHYS_INTERNAL_REGS_DSP	0x2800000
#else
#define PHYS_INTERNAL_PRAM_DSP	0x10100000
#define PHYS_INTERNAL_REGS_DSP	0x10200000
#endif
#define INTERNAL_DSP_PRAM_SIZE	SZ_512K
#define INTERNAL_DSP_REGS_SIZE	SZ_256K
#define PHYS_INTERNAL_QMEM	0x11000000
#define PHYS_INTERNAL_QREG	0x11C00000

#define E50_PAGE_SIZE SZ_4K
#define E50_PAGE_SHIFT 12
#define E50_INPAGE_MASK GENMASK(11, 0)
#define E50_PTE_ENTRIES (E50_PAGE_SIZE / 8)

#define E50_PTE_V_SHIFT		0
#define E50_PTE_V_MASK		BIT(0)
#define E50_PTE_TYPE_SHIFT	1
#define E50_PTE_TYPE_MASK	GENMASK(4, 1)
#define E50_PTE_R_SHIFT		5
#define E50_PTE_R_MASK		BIT(5)
#define E50_PTE_D_SHIFT		6
#define E50_PTE_D_MASK		BIT(6)
#define E50_PTE_PADDR_SHIFT	10

#define E50_ARG_REGS 4

#define ELCORE50_VADDR_START E50_PAGE_SIZE

#define ELCORE50_CACHE_LINE_SIZE 64

#endif
