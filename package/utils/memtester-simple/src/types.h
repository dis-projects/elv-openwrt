/*
 * Copyright (C) 2004-2010 Charles Cazabon <charlesc-memtester@pyropus.ca>
 * Licensed under the terms of the GNU General Public License version 2 (only).
 * Copyright 2018 RnD Center "ELVEES", JSC
 */

#include "sizes.h"

#define EXIT_FAIL_PREPARE   0x01
#define EXIT_FAIL_SUBTEST   0x02

typedef unsigned long ul;
typedef unsigned long long ull;
typedef unsigned long volatile ulv;
typedef unsigned char volatile u8v;
typedef unsigned short volatile u16v;

struct test {
    char *name;
    int (*fp)();
};

union {
    unsigned char bytes[UL_LEN / 8];
    ul val;
} mword8;

union {
    unsigned short u16s[UL_LEN / 16];
    ul val;
} mword16;
