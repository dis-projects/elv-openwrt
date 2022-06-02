// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#include <linux/anon_inodes.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/uaccess.h>

#include "elcore50-syscall.h"

__packed struct timeval_compat{
	uint64_t sec;
	uint64_t usec;
};

__packed struct stat_compat {
	int16_t st_dev;
	uint16_t st_ino;
	uint32_t st_mode;
	uint16_t st_nlink;
	uint16_t st_uid;
	uint16_t st_gid;
	int16_t st_rdev;
	int32_t st_size;
	int32_t st_atime;
	int32_t st_spare1;
	int32_t st_mtime;
	int32_t st_spare2;
	int32_t st_ctime;
	int32_t st_spare3;
	int32_t st_blksize;
	int32_t st_blocks;

	int32_t st_spare4[2];
};

__packed struct tms_compat {
	uint64_t tms_utime;
	uint64_t tms_stime;
	uint64_t tms_cutime;
	uint64_t tms_cstime;
};

static int syscall_gettimeofday(struct timeval_compat *tv)
{
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	tv->sec = ts.tv_sec;
	tv->usec = ts.tv_nsec / 1000;

	if (ts.tv_sec > U32_MAX)
		return -ERANGE;
	return 0;
}

int syscall_handler(struct elcore50_job_inst_desc *job_inst)
{
	struct elcore50_core *core = job_inst->core;
	u32 syscall_idx;
	u64 arg0, arg1, arg2;
	void *virt_arg0, *virt_arg1;
	struct userptr_mapper *mapper;
	size_t offset, size;
	unsigned long flags_state;
	int needFlush, ret;

	job_inst->message.type = ELCORE50_MESSAGE_EMPTY;
	spin_lock_irqsave(&job_inst->state_lock, flags_state);
	job_inst->state = ELCORE50_JOB_STATUS_SYSCALL;
	spin_unlock_irqrestore(&job_inst->state_lock, flags_state);

	arg0 = elcore50_read(core, DSP_R0);
	arg1 = elcore50_read(core, DSP_R1);
	arg2 = elcore50_read(core, DSP_R2);

	if (job_inst->stack_args_size)
		sync_buffer(core, job_inst->stack_args_size,
			    job_inst->stack_start,
			    job_inst->job_desc->stack->mapper,
			    ELCORE50_BUF_SYNC_DIR_TO_CPU);

	syscall_idx = DSP_IRQ_INDEX_SCN(elcore50_read(core, DSP_IRQ_INDEX));
	switch (syscall_idx) {
	case SC_READ: // (int fd, void *buf, size_t cout)
		size = arg2;

		virt_arg0 = elcore50_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		needFlush = 1;
		break;
	case SC_WRITE: // (int fd, void *buf, size_t cout)
		size = arg2;

		virt_arg0 = elcore50_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		needFlush = 0;
		break;
	case SC_GETTIMEOFDAY: // (struct timeval *tv, struct timezone *tz)
		size = sizeof(struct timeval);
		virt_arg0 = elcore50_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;

		job_inst->message.retval = syscall_gettimeofday(virt_arg0);

		sync_buffer(core, size, offset, mapper,
			    ELCORE50_BUF_SYNC_DIR_TO_DEVICE);
	    /* Clear exception bit */

		elcore50_write(elcore50_read(core, DSP_IRQR) & (~IRQR_SC),
			       core, DSP_IRQR);
		elcore50_write(elcore50_read(core, DSP_DQSTR) & (~DQSTR_SC),
			       core, DSP_DQSTR);
		elcore50_write(job_inst->message.retval, core, DSP_R0);
		return 0;
	case SC_OPEN: // (char *filename, int flags, int mode)
		// FIXME: We do not know the real size of filename string
		size = 1280; // 20 cache lines
		virt_arg0 = elcore50_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg0)
			return -EACCES;
		needFlush = 0;
		break;
	case SC_CLOSE: // (int file)
	case SC_ISATTY: // (int file)
		arg1 = arg2 = 0;
	case SC_LSEEK: // (int file, int offset, int dir)
		needFlush = 0;
		break;
	case SC_FSTAT: // (int file, struct stat *st)
		size = sizeof(struct stat_compat);
		virt_arg0 = elcore50_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		arg2 = 0;
		needFlush = 1;
		break;
	case SC_STAT: // (const char *filename, struct stat *buf)
		size = sizeof(struct stat_compat);
		// FIXME: We do not know the real size of filename string
		virt_arg0 = elcore50_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, 1280);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg0)
			return -EACCES;
		virt_arg1 = elcore50_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg1)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		arg2 = 0;
		needFlush = 1;
		break;
	case SC_LINK: // (const char *oldpath, const char *newpath)
		// FIXME: We do not know the real size of filename string
		size = 1280; // 20 cache lines
		virt_arg0 = elcore50_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg0)
			return -EACCES;
		virt_arg1 = elcore50_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg1)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		arg2 = 0;
		needFlush = 0;
		break;
	case SC_UNLINK: // (const char *path)
	case SC_CHDIR: // (const char *path)
		// FIXME: We do not know the real size of filename string
		size = 1280; // 20 cache lines
		virt_arg0 = elcore50_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg0)
			return -EACCES;
		arg1 = arg2 = 0;
		needFlush = 0;
		break;
	case SC_TIMES: // (struct times *buf)
		size = sizeof(struct tms_compat);
		virt_arg0 = elcore50_map_from_users(job_inst, arg0, &mapper,
						    &offset, &arg0, size);
		if (!virt_arg0)
			return -EINVAL;
		if (!arg0)
			return -EACCES;
		arg1 = arg2 = 0;
		needFlush = 1;
		break;
	case SC_GET_ENV: // (char *env, uint32_t *size)
		if (!arg1)
			return -EINVAL;
		size = sizeof(uint32_t);
		virt_arg1 = elcore50_map_from_users(job_inst, arg1, &mapper,
						    &offset, &arg1, size);
		if (!virt_arg1)
			return -EINVAL;
		if (!arg1)
			return -EACCES;
		if (arg0) {
			size = *((u32 *) virt_arg1);
			virt_arg0 = elcore50_map_from_users(job_inst, arg0,
							    &mapper, &offset,
							    &arg0, size);
			if (!virt_arg0)
				return -EINVAL;
			if (!arg0)
				return -EACCES;
		}
		needFlush = 1;
		break;
	default:
		return -EINVAL;
	}

	job_inst->message.arg0 = arg0;
	job_inst->message.arg1 = arg1;
	job_inst->message.arg2 = arg2;
	job_inst->message.num = syscall_idx;
	job_inst->message.type = ELCORE50_MESSAGE_SYSCALL;
	job_inst->syscall_handled = 0;

	wake_up(&job_inst->poll_waitq);
	if (irq_timeout_msec)
		ret = !wait_event_timeout(job_inst->syscall_waitq,
				job_inst->syscall_handled ||
					job_inst->abort,
				msecs_to_jiffies(irq_timeout_msec));
	else {
		wait_event(job_inst->syscall_waitq,
			   job_inst->syscall_handled ||
				job_inst->abort);
		ret = 0;
	}

	job_inst->syscall_handled = 0;
	job_inst->message.type = ELCORE50_MESSAGE_EMPTY;

	if (ret || job_inst->abort)
		return -ETIME;

	if (needFlush) {
		//Flush CPU caches
		sync_buffer(core, size, offset, mapper,
			    ELCORE50_BUF_SYNC_DIR_TO_DEVICE);
	}

	elcore50_write(elcore50_read(core, DSP_IRQR) & (~IRQR_SC), core,
		       DSP_IRQR);
	elcore50_write(elcore50_read(core, DSP_DQSTR) & (~DQSTR_SC), core,
		       DSP_DQSTR);
	elcore50_write(job_inst->message.retval, core, DSP_R0);
	return 0;
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ELcore-50 syscall implementations");
