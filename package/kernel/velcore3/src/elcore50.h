/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright 2018-2019 RnD Center "ELVEES", JSC
 */
#ifndef _LINUX_ELCORE50_H
#define _LINUX_ELCORE50_H

#include <stddef.h>
#include <linux/ioctl.h>
#include <linux/types.h>

#define ELCIOC_MAGIC 'e'

#define SC_GETTIMEOFDAY	1
#define SC_WRITE	2
#define SC_READ		3
#define SC_OPEN		4
#define SC_CLOSE	5
#define SC_FSTAT	6
#define SC_LSEEK	7
#define SC_ISATTY	8
#define SC_CHDIR	9
#define SC_STAT		10
#define SC_TIMES	11
#define SC_LINK		12
#define SC_UNLINK	13
#define SC_GET_ENV	100

#define ELCORE50_MAX_JOB_ARGS 32

#define ELCORE50_MAX_ELF_SECTIONS 64

#define ELCORE50_MAX_JOB_INSTANCE 255

enum elcore50_job_arg_type {
	ELCORE50_TYPE_GLOBAL_MEMORY,
	ELCORE50_TYPE_NC_GLOBAL_MEMORY,
	ELCORE50_TYPE_LOCAL_MEMORY,
	ELCORE50_TYPE_BASIC,
	ELCORE50_TYPE_DMA_MEMORY
};

struct elcore50_job_arg {
	enum elcore50_job_arg_type type;
	union {
		struct {
			int mapper_fd;
		} global_memory;
		struct {
			__u32 size;
		} local_memory;
		struct {
			__u32 size;
			__u64 p;
		} basic;
		struct {
			int mapper_fd;
		} dma_memory;
	};
};

enum elcore50_job_elf_section_type {
	ELCORE50_ELF_SECTION_CODE,
	ELCORE50_ELF_SECTION_DATA,
	ELCORE50_ELF_SECTION_DATA_CONST,
	ELCORE50_ELF_SECTION_LAST = ELCORE50_ELF_SECTION_DATA_CONST
};

struct elcore50_job_elf_section {
	enum elcore50_job_elf_section_type type;
	int mapper_fd;
	__u32 size;
	__u32 elcore_virtual_address;
};

enum elcore50_message_type {
	ELCORE50_MESSAGE_EMPTY = 0,
	ELCORE50_MESSAGE_SYSCALL_REPLY = 1,
	ELCORE50_MESSAGE_SYSCALL = 2,
};

struct elcore50_message {
	enum elcore50_message_type type;
	int num;
	__u64 arg0;
	__u64 arg1;
	__u64 arg2;
	__s64 retval;
};

struct elcore50_job {
	__u32 num_elf_sections;
	struct elcore50_job_elf_section elf_sections[ELCORE50_MAX_ELF_SECTIONS];
	int hugepages;
	int stack_fd;
	int job_fd;
};

struct elcore50_job_instance {
	int job_fd;
	__u32 argc;
	struct elcore50_job_arg args[ELCORE50_MAX_JOB_ARGS];
	__u32 entry_point_virtual_address;
	__u32 launcher_virtual_address;
	char name[255];
	int debug_enable;

	int job_instance_fd;
	int debug_fd;
};

struct elcore50_job_instance_info {
	long id;
	int pid;
	char name[255];
};

struct elcore50_job_instance_list {
	__u32 job_instance_count;
	struct elcore50_job_instance_info *info;
	__u32 job_instance_ret;
};

enum elcore50_job_instance_state {
	ELCORE50_JOB_STATUS_ENQUEUED,
	ELCORE50_JOB_STATUS_RUN,
	ELCORE50_JOB_STATUS_INTERRUPTED,
	ELCORE50_JOB_STATUS_SYSCALL,
	ELCORE50_JOB_STATUS_DONE
};

enum elcore50_job_instance_error {
	ELCORE50_JOB_STATUS_SUCCESS,
	ELCORE50_JOB_STATUS_ERROR
};

struct elcore50_job_instance_status {
	int job_instance_fd;
	enum elcore50_job_instance_state state;
	enum elcore50_job_instance_error error;
};

struct elcore50_job_instance_dbg {
	long job_instance_id;
	int job_instance_dbg_fd;
};

struct elcore_caps {
	char drvname[32];
	__u32 hw_id;
};

struct elcore50_device_info {
	int nclusters;
	int cluster_id;
	int cluster_cap;
	int core_in_cluster_id;
};

enum elcore50_buf_type {
	ELCORE50_CACHED_BUFFER_FROM_UPTR,
	ELCORE50_NONCACHED_BUFFER
};

struct elcore50_buf {
	int dmabuf_fd;
	int mapper_fd;
	enum elcore50_buf_type type;
	__u64 p;
	__u64 size;
};

enum elcore50_buf_sync_dir {
	ELCORE50_BUF_SYNC_DIR_TO_CPU,
	ELCORE50_BUF_SYNC_DIR_TO_DEVICE
};

struct elcore50_buf_sync {
	int mapper_fd;
	size_t offset;
	size_t size;
	enum elcore50_buf_sync_dir dir;
};

struct elcore50_dbg_mem {
	__u64 vaddr;
	size_t size;
	void *data;
};

enum elcore50_stop_reason {
	ELCORE50_STOP_REASON_HW_BREAKPOINT,
	ELCORE50_STOP_REASON_SW_BREAKPOINT,
	ELCORE50_STOP_REASON_EXTERNAL_REQUEST,
	ELCORE50_STOP_REASON_STEP,
	ELCORE50_STOP_REASON_DBG_INTERRUPT,
	ELCORE50_STOP_REASON_APP_EXCEPTION
};

struct elcore50_dbg_stop_reason {
	enum elcore50_stop_reason reason;
};


#define ELCORE50_IOC_ENQUEUE_JOB \
	_IOWR(ELCIOC_MAGIC, 1, struct elcore50_job_instance *)

#define ELCORE50_IOC_GET_JOB_STATUS \
	_IOWR(ELCIOC_MAGIC, 2, struct elcore50_job_status *)

#define ELCORE50_IOC_GET_CORE_IDX \
	_IOR(ELCIOC_MAGIC, 3, struct elcore50_device_info *)

#define ELCORE50_IOC_CREATE_BUFFER \
	_IOR(ELCIOC_MAGIC, 4, struct elcore50_buf *)

#define ELCORE50_IOC_CREATE_MAPPER \
	_IOR(ELCIOC_MAGIC, 5, struct elcore50_buf *)

#define ELCORE50_IOC_SYNC_BUFFER \
	_IOR(ELCIOC_MAGIC, 6, struct elcore50_buf_sync *)

#define ELCORE50_IOC_CREATE_JOB \
	_IOR(ELCIOC_MAGIC, 7, struct elcore50_job *)

#define ELCORE50_IOC_GET_JOB_COUNT \
	_IOR(ELCIOC_MAGIC, 8, __u32 *)

#define ELCORE50_IOC_GET_JOB_LIST \
	_IOWR(ELCIOC_MAGIC, 9, struct elcore50_job_instance_list *)

#define ELCORE50_IOC_DBG_JOB_ATTACH \
	_IOR(ELCIOC_MAGIC, 10, struct elcore50_job_instance_dbg *)

#define ELCORE50_IOC_DBG_MEMORY_READ \
	_IOWR(ELCIOC_MAGIC, 11, struct elcore50_dbg_mem *)

#define ELCORE50_IOC_DBG_MEMORY_WRITE \
	_IOWR(ELCIOC_MAGIC, 12, struct elcore50_dbg_mem *)

#define ELCORE50_IOC_DBG_REGISTER_READ \
	_IOWR(ELCIOC_MAGIC, 13, struct elcore50_dbg_mem *)

#define ELCORE50_IOC_DBG_REGISTER_WRITE \
	_IOWR(ELCIOC_MAGIC, 14, struct elcore50_dbg_mem *)

#define ELCORE50_IOC_DBG_JOB_INSTANCE_INTERRUPT \
	_IO(ELCIOC_MAGIC, 15)

#define ELCORE50_IOC_DBG_JOB_INSTANCE_CONTINUE \
	_IO(ELCIOC_MAGIC, 16)

#define ELCORE50_IOC_DBG_GET_STOP_REASON \
	_IOWR(ELCIOC_MAGIC, 17, struct elcore50_dbg_stop_reason *)

#define ELCORE50_IOC_DBG_HW_BREAKPOINT_SET \
	_IOWR(ELCIOC_MAGIC, 18, __u32 *)

#define ELCORE50_IOC_DBG_HW_BREAKPOINT_CLEAR \
	_IOWR(ELCIOC_MAGIC, 19, __u32 *)

#define ELCORE50_IOC_DBG_STEP \
	_IOWR(ELCIOC_MAGIC, 20, __u32 *)

#define ELCIOC_GET_CAPS \
	_IOR(ELCIOC_MAGIC, 255, struct elcore_caps *)

#endif
