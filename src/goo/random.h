/*!
 * random.c - random number generation for C
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#ifndef _GOO_RANDOM_H
#define _GOO_RANDOM_H

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

void
goo_poll(void);

int
goo_random(void *dst, size_t len);

#if defined(__cplusplus)
}
#endif

#endif
