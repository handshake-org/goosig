/*!
 * random.cc - random number generation
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#ifndef _GOO_RANDOM_H
#define _GOO_RANDOM_H

#include <stdlib.h>

void
goo_poll(void);

int
goo_random(void *dst, size_t len);

#endif
