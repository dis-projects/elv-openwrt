/*
 * Copyright (C) 2004-2012 Charles Cazabon <charlesc-memtester@pyropus.ca>
 * Licensed under the terms of the GNU General Public License version 2 (only).
 * Copyright 2019-2021 RnD Center "ELVEES", JSC
 */

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include "types.h"
#include "sizes.h"

#define ALIGN(x,a)              __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)    ((((ul)x) + ((ul)mask)) & ~((ul)mask))

/* Some systems don't define MAP_LOCKED.  Define it to 0 here
   so it's just a no-op when ORed with other constants. */
#ifndef MAP_LOCKED
#define MAP_LOCKED 0
#endif

int test_solidbits_comparison(unsigned long volatile *bufa,
                              unsigned long volatile *bufb, size_t count,
                              int id, int cycles, int cmp_num);
int test_bitflip_comparison(unsigned long volatile *bufa,
                            unsigned long volatile *bufb, size_t count, int id,
                            int cycles, int cmp_num);

int test_randdata(unsigned long volatile *bufa,
                            unsigned long volatile *bufb, size_t count, int id,
                            int cycles, int cmp_num);

/* Global vars - so tests have access to this information */
int id;
int verbose = 0;
int stop_on_error = 1;
ulv available_bit_mask = UL_ONEBITS;

struct test tests[] = {
    {"Solid Bits", test_solidbits_comparison},
    {"Bit Flip", test_bitflip_comparison},
    {"Random data", test_randdata},
    {NULL, NULL}
};

void usage(char *me)
{
    printf("Usage: %s [-p physaddrbase [-b bitmask]] [-m testmask] ", me);
    printf("[-w writes] [-r reads] [-i id] <mem>B|K|M [loops] [-e]\n");
    printf(" -e - continue on error (default stop on error)\n");
    printf(" -v - verbose\n");
    printf(" -h - display usage and exit\n");
    printf(" -m - defines test mask (default 7)\n");
    printf("  1 - solid bits, 2 - bit flip, 4 - Random data\n");
    printf(" -p - physical address (by default malloc() is used)\n");
    printf(" -b - available bit mask at %d-bit access (default 0x%lx)\n",
           UL_LEN, UL_ONEBITS);
    printf(" -w - number of writing cycles (default 1)\n");
    printf(" -r - number of comparing cycles per write (default 1)\n");
    printf(" -i - id of the application (default 0)\n");
    printf(" <mem>B|K|M - testing memory size in B|KB|MB. "
           "No suffix means MB\n");
    printf(" loops - number of full read/write cycles (default 1)\n");
    printf("Example: %s -m 1 -w 5 -r 2 -i 1 100M 5\n", me);
}

#ifdef _SC_PAGE_SIZE
long get_pagesize(void)
{
    long pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize != -1)
        printf("memtester-simple #%d: pagesize is %ld\n", id, pagesize);

    return pagesize;
}
#else
int get_pagesize(void)
{
    return -1;
}
#endif

int main(int argc, char **argv)
{
    ul loops = 1, loop, i;
    int scycles = 1, cmp_num = 1;
    size_t pagesize, wantraw, wantmb, wantbytes, wantbytes_orig, wantbytes_aligned,
           bufsize, halflen, count;
    off_t physaddrbase = -1, physaddrbase_aligned;
    off_t offset = 0;
    char *memsuffix, *addrsuffix, *loopsuffix;
    void volatile *buf, *aligned;
    ulv *bufa, *bufb;
    int do_mlock = 1, done_mem = 0;
    int exit_code = 0;
    int memfd, opt, memshift;
    size_t maxbytes = -1;                   /* addressable memory, in bytes */
    size_t maxmb = (maxbytes >> 20) + 1;    /* addressable memory, in MB */
    /* Device to mmap memory from with -p, default is normal core */
    char *device_name = "/dev/mem";
    struct stat statbuf;
    ul testmask = 7;

    pagesize = get_pagesize();
    if (pagesize == -1)
        err(EXIT_FAIL_PREPARE, "Failed to get pagesize.");

    while ((opt = getopt(argc, argv, "i:p:b:w:r:m:hev")) != -1) {
        switch (opt) {
        case 'p':
            errno = 0;
            physaddrbase = (off_t) strtoull(optarg, &addrsuffix, 16);
            if (errno != 0) {
                err(EXIT_FAIL_PREPARE,
                      "failed to parse physaddrbase arg; should be hex "
                      "address (0x123...)");
            }
            if (*addrsuffix != '\0') {
                /* got an invalid character in the address */
                err(EXIT_FAIL_PREPARE,
                      "failed to parse physaddrbase arg; should be hex "
                      "address (0x123...)");
            }
            physaddrbase_aligned = physaddrbase & ~(pagesize - 1);
            break;
        case 'b':
            errno = 0;
            available_bit_mask = strtoul(optarg, &addrsuffix, 16);
            if (errno != 0) {
                err(EXIT_FAIL_PREPARE,
                      "failed to parse bitmask arg; should be hex "
                      "address (0x123...)");
            }
            if (*addrsuffix != '\0') {
                /* got an invalid character in the address */
                err(EXIT_FAIL_PREPARE,
                      "failed to parse bitmask arg; should be hex "
                      "address (0x123...)");
            }
            break;
        case 'i':
            id = atoi(optarg);
            break;
        case 'w':
            scycles = atoi(optarg);
            break;
        case 'r':
            cmp_num = atoi(optarg);
            break;
        case 'm':
            testmask = atoi(optarg) & 7;
            break;
        case 'e':
            stop_on_error = 0;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage(argv[0]);
            return EXIT_SUCCESS;
        }
    }

    if (optind >= argc)
        err(EXIT_FAIL_PREPARE,
              "memtester-simple #%d: need memory argument, in B|K|M", id);

    errno = 0;
    wantraw = (size_t) strtoul(argv[optind], &memsuffix, 0);
    if (errno != 0)
        err(EXIT_FAIL_PREPARE,
              "memtester-simple #%d: failed to parse memory argument", id);

    switch (*memsuffix) {
    case 'M':
    case 'm':
    case '\0': /* no suffix */
        memshift = 20; /* megabytes */
        break;
    case 'K':
    case 'k':
        memshift = 10; /* kilobytes */
        break;
    case 'B':
    case 'b':
        memshift = 0; /* bytes*/
        break;
    default:
        /* bad suffix */
        usage(argv[0]); /* doesn't return */
    }
    wantbytes_orig = wantbytes = ((size_t) wantraw << memshift);
    wantmb = (wantbytes_orig >> 20);
    optind++;
    if (wantmb > maxmb)
        err(EXIT_FAIL_PREPARE,
              "memtester-simple #%d: this system can only address %llu MB.",
              id, (ull) maxmb);

    if ((physaddrbase == -1) && (wantbytes < pagesize))
        err(EXIT_FAIL_PREPARE,
              "memtester-simple #%d: bytes %ld < pagesize %ld -- memory argument too large?",
              id, wantbytes, pagesize);

    if (optind >= argc) {
        loops = 1;
    } else {
        errno = 0;
        loops = strtoul(argv[optind], &loopsuffix, 0);
        if (errno != 0)
            err(EXIT_FAIL_PREPARE,
                  "memtester-simple #%d: failed to parse number of loops", id);

        if (*loopsuffix != '\0')
            err(EXIT_FAIL_PREPARE,
                  "memtester-simple #%d: loop suffix %c", id, *loopsuffix);
    }

    printf("memtester-simple #%d: want %lluMB (%llu bytes)\n", id,
           (ull) wantmb, (ull) wantbytes);
    buf = NULL;

    if (physaddrbase != -1) {
        offset = physaddrbase - physaddrbase_aligned;
        wantbytes += offset;

        memfd = open(device_name, O_RDWR | O_SYNC);
        if (memfd == -1) {
            err(EXIT_FAIL_PREPARE,
                  "failed to open %s for physical memory: %s",
                  device_name, strerror(errno));
        }
        wantbytes_aligned = ((wantbytes + pagesize - 1) / pagesize) * pagesize;
        buf = (void volatile *) mmap(0, wantbytes_aligned, PROT_READ | PROT_WRITE,
                                     MAP_SHARED | MAP_LOCKED, memfd,
                                     physaddrbase_aligned);
        if (buf == MAP_FAILED) {
            err(EXIT_FAIL_PREPARE,
                  "failed to mmap %s for physical memory: %s",
                  device_name, strerror(errno));
        }

        if (mlock((void *) buf, wantbytes_aligned) < 0) {
            err(0, "failed to mlock mmap'ed space");
            do_mlock = 0;
        }

        bufsize = wantbytes; /* accept no less */
        aligned = buf;
        done_mem = 1;
    }

    while (!done_mem) {
        while (!buf && wantbytes) {
            buf = (void volatile *)malloc(wantbytes);
            if (!buf)
                wantbytes -= pagesize;
        }
        bufsize = wantbytes;
        printf("got  %lluMB (%llu bytes)", (ull) wantbytes >> 20,
               (ull) wantbytes);
        fflush(stdout);
        if (do_mlock) {
            printf(", trying mlock ...");
            fflush(stdout);
            if ((size_t) buf % pagesize) {
                aligned = ALIGN(buf, pagesize);
                bufsize -= ((size_t) aligned - (size_t) buf);
            } else {
                aligned = buf;
            }
            if (mlock((void *)aligned, bufsize) < 0) {
                switch (errno) {
                case EAGAIN:    /* BSDs */
                    printf("memtester-simple #%d: over system/pre-process limit, reducing...\n",
                           id);
                    free((void *)buf);
                    buf = NULL;
                    wantbytes -= pagesize;
                    break;
                case ENOMEM:
                    printf("memtester-simple #%d: Failed to get memory...\n", id);
                    free((void *)buf);
                    buf = NULL;
                    wantbytes -= pagesize;
                    break;
                case EPERM:
                    printf("memtester-simple #%d: insufficient permission.\n", id);
                    printf("memtester-simple #%d: trying again, unlocked:\n", id);
                    do_mlock = 0;
                    free((void *)buf);
                    buf = NULL;
                    wantbytes = wantbytes_orig;
                    break;
                default:
                    printf("memtester-simple #%d: failed for unknown reason.\n", id);
                    do_mlock = 0;
                    done_mem = 1;
                }
            } else {
                printf(" locked.\n");
                done_mem = 1;
            }
        } else {
            done_mem = 1;
            printf("\n");
        }
    }

    if (!do_mlock)
        err(1,
              "memtester-simple #%d, continuing with unlocked memory; testing "
              "will be slower and less reliable.", id);

    halflen = (bufsize - offset) / 2;
    count = halflen / sizeof(ul);
    bufa = (ulv *) ((size_t) aligned + offset);
    bufb = (ulv *) ((size_t) aligned + halflen + offset);

    for (loop = 1; ((!loops) || loop <= loops); loop++) {
        printf("memtester-simple #%d: Loop %lu/%lu:\n", id, loop,
               loops);
        fflush(stdout);
        for (i = 0;; i++) {
            if (!tests[i].name)
                break;

            if (testmask && (!((1 << i) & testmask))) {
                continue;
            }

            fflush(stdout);
            if (!tests[i].fp(bufa, bufb, count, scycles, cmp_num)) {
                printf("memtester-simple #%d: %s: ok\n", id,
                       tests[i].name);
                fflush(stdout);
            } else {
                printf("memtester-simple #%d: %s: FAILURE\n",
                       id, tests[i].name);
                fflush(stdout);
                exit_code |= EXIT_FAIL_SUBTEST;
            }
        }
        if (stop_on_error && exit_code)
            break;
    }

    if (do_mlock)
        if (physaddrbase != -1)
            munlock((void *)aligned, wantbytes_aligned);
        else
            munlock((void *)aligned, bufsize);

    printf("memtester-simple #%d: Done.\n", id);
    fflush(stdout);

    return exit_code;
}
