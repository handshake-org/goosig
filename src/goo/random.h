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
