/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#ifndef _LINUX_ELCORE50_SYSCALL_H
#define _LINUX_ELCORE50_SYSCALL_H

#include "elcore50-job-instance.h"

int syscall_handler(struct elcore50_job_inst_desc *job_inst);

#endif
