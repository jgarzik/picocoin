/*
 * prng.c
 *		Wrapper for builtin functions
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
 * contrib/pgcrypto/internal.c
 */

#include <ccoin/crypto/fortuna.h> // for fortuna_add_entropy, etc
#include <ccoin/crypto/prng.h>

#include <stdlib.h> // for NULL
#include <string.h> // for memset
#include <time.h>   // for time_t, time

/*
 * Randomness provider
 */

static time_t seed_time = 0;
static time_t check_time = 0;

static void system_reseed(void) {
    uint8_t buf[1024];
    int n;
    time_t t;
    int skip = 1;

    t = time(NULL);

    if (seed_time == 0)
        skip = 0;
    else if ((t - seed_time) < SYSTEM_RESEED_MIN)
        skip = 1;
    else if ((t - seed_time) > SYSTEM_RESEED_MAX)
        skip = 0;
    else if (check_time == 0 || (t - check_time) > SYSTEM_RESEED_CHECK_TIME) {
        check_time = t;

        /* roll dice */
        prng_get_random_bytes(buf, 1);
        skip = buf[0] >= SYSTEM_RESEED_CHANCE;
    }
    /* clear 1 byte */
    memset(buf, 0, sizeof(buf));

    if (skip)
        return;

    n = prng_acquire_system_randomness(buf);
    if (n > 0)
        fortuna_add_entropy(buf, n);

    seed_time = t;
    memset(buf, 0, sizeof(buf));
}

int prng_get_random_bytes(uint8_t *dst, unsigned count) {
    system_reseed();
    fortuna_get_bytes(count, dst);
    return 0;
}

int prng_add_entropy(const uint8_t *data, unsigned count) {
    system_reseed();
    fortuna_add_entropy(data, count);
    return 0;
}