/*
 * random.c
 *		Acquire randomness from system.  For seeding RNG.
 *
 * Copyright (c) 2001 Marko Kreen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * contrib/pgcrypto/random.c
 */

#include "picocoin-config.h"

#ifdef USE_VALGRIND
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_DEFINED(addr, size)                                  \
    do {                                                                       \
    } while (0)
#endif

#include <ccoin/crypto/sha1.h> // for sha1_Update, SHA1_CTX, etc

#include <errno.h>  // for EINTR, errno
#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t
#include <stdlib.h> // for free, malloc, random
#include <string.h> // for memset, NULL

/* how many bytes to ask from system random provider */
#define RND_BYTES 32

/*
 * Try to read from /dev/urandom or /dev/random on these OS'es.
 *
 * The list can be pretty liberal, as the device not existing
 * is expected event.
 */
#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) ||      \
    defined(__NetBSD__) || defined(__DragonFly__) || defined(__darwin__) ||    \
    defined(__SOLARIS__) || defined(__hpux) || defined(__HPUX__) ||            \
    defined(__CYGWIN__) || defined(_AIX)

#define TRY_DEV_RANDOM

#include <fcntl.h>  // for open
#include <unistd.h> // for close, getpid, read, pid_t

static int safe_read(int fd, void *buf, size_t count) {
    int done = 0;
    char *p = buf;
    int res;

    while (count) {
        res = read(fd, p, count);
        if (res <= 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += res;
        done += res;
        count -= res;
    }
    return done;
}

static uint8_t *try_dev_random(uint8_t *dst) {
    int fd;
    int res;

    fd = open("/dev/urandom", O_RDONLY, 0);
    if (fd == -1) {
        fd = open("/dev/random", O_RDONLY, 0);
        if (fd == -1)
            return dst;
    }
    res = safe_read(fd, dst, RND_BYTES);
    close(fd);
    if (res > 0)
        dst += res;
    return dst;
}
#endif

/*
 * Try to find randomness on Windows
 */
#ifdef WIN32

#define TRY_WIN32_GENRAND
#define TRY_WIN32_PERFC

#include <wincrypt.h>
#include <windows.h>

/*
 * this function is from libtomcrypt
 *
 * try to use Microsoft crypto API
 */
static uint8_t *try_win32_genrand(uint8_t *dst) {
    int res;
    HCRYPTPROV h = 0;

    res = CryptAcquireContext(&h, NULL, MS_DEF_PROV, PROV_RSA_FULL,
                              (CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET));
    if (!res)
        res = CryptAcquireContext(&h, NULL, MS_DEF_PROV, PROV_RSA_FULL,
                                  CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET |
                                      CRYPT_NEWKEYSET);
    if (!res)
        return dst;

    res = CryptGenRandom(h, RND_BYTES, dst);
    if (res == TRUE)
        dst += RND_BYTES;

    CryptReleaseContext(h, 0);
    return dst;
}

static uint8_t *try_win32_perfc(uint8_t *dst) {
    int res;
    LARGE_INTEGER time;

    res = QueryPerformanceCounter(&time);
    if (!res)
        return dst;

    memcpy(dst, &time, sizeof(time));
    return dst + sizeof(time);
}
#endif /* WIN32 */

/*
 * If we are not on Windows, then hopefully we are
 * on a unix-like system.  Use the usual suspects
 * for randomness.
 */
#ifndef WIN32

#define TRY_UNIXSTD

#include <sys/time.h> // for gettimeofday, timeval
#include <sys/types.h>
#include <time.h>
#include <unistd.h> // for close, getpid, read, pid_t

/*
 * Everything here is predictible, only needs some patience.
 *
 * But there is a chance that the system-specific functions
 * did not work.  So keep faith and try to slow the attacker down.
 */
static uint8_t *try_unix_std(uint8_t *dst) {
    pid_t pid;
    int x;

    struct timeval tv;
    int res;

    /* process id */
    pid = getpid();
    memcpy(dst, (uint8_t *)&pid, sizeof(pid));
    dst += sizeof(pid);

    /* time */
    gettimeofday(&tv, NULL);
    memcpy(dst, (uint8_t *)&tv, sizeof(tv));
    dst += sizeof(tv);

    /* pointless, but should not hurt */
    x = random();
    memcpy(dst, (uint8_t *)&x, sizeof(x));
    dst += sizeof(x);

    /* hash of uninitialized stack and heap allocations */
    SHA1_CTX ctx;
    sha1_Init(&ctx);

    uint8_t *ptr;
    uint8_t stack[8192];
    int alloc = 32 * 1024;

    VALGRIND_MAKE_MEM_DEFINED(stack, sizeof(stack));
    sha1_Update(&ctx, stack, sizeof(stack));
    ptr = malloc(alloc);
    VALGRIND_MAKE_MEM_DEFINED(ptr, alloc);
    sha1_Update(&ctx, ptr, alloc);
    free(ptr);

    sha1_Final(dst, &ctx);
    memset(&ctx, 0, sizeof(SHA1_CTX));

    dst += SHA1_DIGEST_LENGTH;

    return dst;
}
#endif

/*
 * try to extract some randomness for initial seeding
 *
 * dst should have room for 1024 bytes.
 */
unsigned prng_acquire_system_randomness(uint8_t *dst) {
    uint8_t *p = dst;

#ifdef TRY_DEV_RANDOM
    p = try_dev_random(p);
#endif
#ifdef TRY_WIN32_GENRAND
    p = try_win32_genrand(p);
#endif
#ifdef TRY_WIN32_PERFC
    p = try_win32_perfc(p);
#endif
#ifdef TRY_UNIXSTD
    p = try_unix_std(p);
#endif
    return p - dst;
}
