/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2021 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_ELCORE50_JOB_INSTANCE_H
#define _LINUX_ELCORE50_JOB_INSTANCE_H

#include "elcore50-mapper.h"
#include "elcore50-job.h"

#define E50_CACHE_TIMEOUT_USEC 10000

extern int mod_caches;
extern u32 irq_timeout_msec;
extern const struct file_operations elcore50_mapper_ops;
extern const struct file_operations elcore50_job_fops;
extern const struct dma_buf_ops elcore50_dmabuf_ops;

enum elcore50_l2_size {
	L2_CACHE_NONE = 0,
	L2_CACHE_128 = 1,
	L2_CACHE_256 = 2,
	L2_CACHE_512 = 3
};

enum elcore50_debug_state {
	ELCORE50_DBG_RUN,
	ELCORE50_DBG_INTERRUPTED,
	ELCORE50_DBG_EXITED,
	ELCORE50_DBG_LAST,
};

enum elcore50_debug_request {
	DBG_REQUEST_NONE,
	DBG_REQUEST_IOCTL,
	DBG_REQUEST_ATTACH,
	DBG_REQUEST_DETACH,
	DBG_READY_TO_PROCESS,
	DBG_PROCESSED,
};

/*
 * Internal job instance data structure
 */
struct elcore50_job_inst_desc {
	struct elcore50_core *core;
	struct elcore50_buf_desc **args;
	int argc;
	uint32_t *local_args_addr;
	enum elcore50_job_instance_state state;
	enum elcore50_job_instance_error error;
	uint32_t launcher_vaddr;
	uint32_t entry_point_vaddr;
	uint32_t noncached_regions;
	struct list_head queue_node;
	wait_queue_head_t poll_waitq;
	wait_queue_head_t poll_dbg_waitq;
	wait_queue_head_t irq_waitq;
	wait_queue_head_t syscall_waitq;
	wait_queue_head_t debug_waitq;
	struct work_struct worker;
	enum elcore50_l2_size l2_size;
	uint32_t nc_mem_current;
	struct mmu_pool *dsp_pool;
	struct mmu_pool *dma_pool;
#ifndef ELCORE50_NO_IRQS
	int core_stopped;
#endif
	int abort;
	size_t stack_start;
	void *stack_args;
	size_t stack_args_size;
	uint64_t arg_regs[E50_ARG_REGS];
	spinlock_t state_lock;
	struct mutex debug_lock;

	struct file **arg_files;

	struct elcore50_message message;
	int syscall_handled;

	int pid;
	char name[255];

	int self_fd;

	int attached;
	enum elcore50_debug_state debug_state;
	enum elcore50_stop_reason stop_reason;
	enum elcore50_debug_request debug_request;
	int debug_result;
	int step_breakpoint;
	u32 dbsar_value;
	u32 dbsar_addr;
	u32 dbcnt_rest_plus_1;

	struct file *job_file;
	struct elcore50_job_desc *job_desc;
};

int elcore50_cancel_job_inst(struct elcore50_job_inst_desc *instance);
int elcore50_enqueue_job_inst(struct elcore50_core *core, void __user *arg);
int elcore50_get_job_inst_count(struct elcore50_core *core, void __user *arg);
int elcore50_get_job_inst_list(struct elcore50_core *core, void __user *arg);
void elcore50_job_inst_run(struct work_struct *worker);
long elcore50_get_job_inst_status(struct elcore50_core *core,
				  void __user *arg);
void *elcore50_map_from_users(struct elcore50_job_inst_desc *instance,
			      u64 vaddr, struct userptr_mapper **out_mapper,
			      size_t *offset, u64 *user_vaddr_cpu,
			      size_t size);
#endif
