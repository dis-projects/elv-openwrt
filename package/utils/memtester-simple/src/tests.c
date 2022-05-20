/*
 * Copyright (C) 2004-2012 Charles Cazabon <charlesc-memtester@pyropus.ca>
 * Licensed under the terms of the GNU General Public License version 2 (only).
 * Copyright 2019 RnD Center "ELVEES", JSC
 */

#include <sys/types.h>
#include <sys/random.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <error.h>

#include "types.h"
#include "sizes.h"

extern int id;
extern int verbose;
extern int stop_on_error;
extern ulv available_bit_mask;

int compare_regions_bfailure(ulv * bufa, ulv * bufb, size_t count)
{
    int r = 0;
    size_t i;
    ulv *p1 = bufa;
    ulv *p2 = bufb;

    for (i = 0; i < count; i++, p1++, p2++) {
        if ((*p1 & available_bit_mask) != (*p2 & available_bit_mask)) {
            r += 1;
            if (verbose) {
                error(0, 0,
                      "memtester-simple #%d: FAILURE: 0x%08lx != 0x%08lx at offset 0x%08lx.\n",
                      id, (ul) *p1 & available_bit_mask, (ul) *p2 & available_bit_mask, (ul) (i * sizeof(ul)));

                if ((((*p1 & available_bit_mask) >> 24) & 0xff) !=
                                (((*p2 & available_bit_mask) >> 24) & 0xff))
                    error(0, 0, "#%d: failure in byte 3\n", id);
                if ((((*p1 & available_bit_mask) >> 16) & 0xff) !=
                                (((*p2 & available_bit_mask) >> 16) & 0xff))
                    error(0, 0, "#%d: failure in byte 2\n", id);
                if ((((*p1 & available_bit_mask) >> 8) & 0xff) !=
                                (((*p2 & available_bit_mask) >> 8) & 0xff))
                    error(0, 0, "#%d: failure in byte 1\n", id);
                if ((((*p1 & available_bit_mask) >> 0) & 0xff) !=
                                (((*p2 & available_bit_mask) >> 0) & 0xff))
                    error(0, 0, "#%d: failure in byte 0\n", id);
            }

            if (stop_on_error)
                return r;
        }
    }
    return r;
}

int test_solidbits_comparison(ulv * bufa, ulv * bufb, size_t count, int cycles,
                              int cmp_num)
{
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    unsigned int j, k, errors, was_err = 0, total_errors = 0;
    ul q;
    size_t i;
    for (j = 0; j < cycles; j++) {
        q = (j % 2) == 0 ? UL_ONEBITS : 0;
        p1 = (ulv *) bufa;
        p2 = (ulv *) bufb;
        for (i = 0; i < count; i++) {
            *p1++ = *p2++ = (i % 2) == 0 ? q : ~q;
        }
        for (k = 0; k < cmp_num; k++) {
            errors = compare_regions_bfailure(bufa, bufb, count);
            if (stop_on_error && errors)
                return -1;
            if (errors) {
                total_errors += errors;
                was_err = 1;
            }
        }
    }
    printf("memtester-simple #%d: Total errors %d\n", id, total_errors);
    if (was_err)
        return -1;
    else
        return 0;
}

int test_bitflip_comparison(ulv * bufa, ulv * bufb, size_t count, int cycles,
                            int cmp_num)
{
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    unsigned int j, k, errors, was_err = 0, total_errors = 0;
    ul q;
    size_t i;

    for (k = 0; k < UL_LEN; k++) {
        q = ONE << k;
        for (j = 0; j < cycles; j++) {
            q = ~q;
            p1 = (ulv *) bufa;
            p2 = (ulv *) bufb;
            for (i = 0; i < count; i++) {
                *p1++ = *p2++ = (i % 2) == 0 ? q : ~q;
            }

            for (i = 0; i < cmp_num; i++) {
                errors = compare_regions_bfailure(bufa, bufb, count);
                if (stop_on_error && errors)
                    return -1;
                if (errors) {
                    total_errors += errors;
                    was_err = 1;
                }
            }

        }
    }

    printf("memtester-simple #%d: Total errors %d\n", id, total_errors);
    if (was_err)
        return -1;
    else
        return 0;
}

int test_randdata(ulv * bufa, ulv * bufb, size_t count, int cycles, int cmp_num)
{
    ulv *p1 = bufa;
    ulv *p2 = bufb;
    unsigned int j, k, errors, was_err = 0, total_errors = 0;
    ul q;
    size_t i;
    unsigned long *cmprand = calloc(count, sizeof(unsigned long));
    unsigned long *p3 = cmprand;

    for (j = 0; j < cycles; j++) {
        p1 = (ulv *) bufa;
        p2 = (ulv *) bufb;
        p3 = cmprand;
        // TODO: Replace with rand() that takes SEED from environment variable
        getrandom(cmprand, count * sizeof(ulv), 0);
        for (i = 0; i < count; i++) {
            *p1++ = *p2++ = *p3++;
        }
        for (k = 0; k < cmp_num; k++) {
            errors = compare_regions_bfailure(bufa, cmprand, count);
            errors += compare_regions_bfailure(bufb, cmprand, count);
            if (stop_on_error && errors)
                return -1;
            if (errors) {
                total_errors += errors;
                was_err = 1;
            }
        }
    }
    printf("memtester-simple #%d: Total errors %d\n", id, total_errors);
    if (was_err)
        return -1;
    else
        return 0;
}
