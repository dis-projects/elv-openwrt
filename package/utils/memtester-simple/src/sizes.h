/*
 * Copyright (C) 2004-2012 Charles Cazabon <charlesc-memtester@pyropus.ca>
 * Licensed under the terms of the GNU General Public License version 2 (only).
 * Copyright 2019 RnD Center "ELVEES", JSC
 */

#include <limits.h>

#define ONE 0x00000001L

#if (ULONG_MAX == 4294967295UL)
#define UL_ONEBITS 0xffffffff
#define UL_LEN 32
#elif (ULONG_MAX == 18446744073709551615ULL)
#define UL_ONEBITS 0xffffffffffffffffUL
#define UL_LEN 64
#else
#error long on this platform is not 32 or 64 bits
#endif
