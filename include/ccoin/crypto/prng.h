/*
 * prng.h
 *		Header file for pgcrypto.
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
 * contrib/pgcrypto/px.h
 */

#ifndef __PRNG_H
#define __PRNG_H

#include <stdint.h> // for uint8_t

/*
 * System reseeds should be separated at least this much.
 */
#define SYSTEM_RESEED_MIN (20 * 60) /* 20 min */

/*
 * How often to roll dice.
 */
#define SYSTEM_RESEED_CHECK_TIME (10 * 60) /* 10 min */

/*
 * The chance is x/256 that the reseed happens.
 */
#define SYSTEM_RESEED_CHANCE (4) /* 256/4 * 10min ~ 10h */

/*
 * If this much time has passed, force reseed.
 */
#define SYSTEM_RESEED_MAX (12 * 60 * 60) /* 12h */

int prng_get_random_bytes(uint8_t *dst, unsigned count);
unsigned prng_acquire_system_randomness(uint8_t *dst);

#endif /* __PRNG_H */
