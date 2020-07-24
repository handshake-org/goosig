/*!
 * util.h - utils for libgoo
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#ifndef _GOO_UTIL_H
#define _GOO_UTIL_H

#include <stdio.h>
#include <stdlib.h>

#define ASSERT(expr) do {                         \
  if (!(expr))                                    \
    __goo_assert_fail(__FILE__, __LINE__, #expr); \
} while (0)

static void
__goo_assert_fail(const char *file, int line, const char *expr) {
  fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", file, line, expr);
  fflush(stderr);
  abort();
}

#endif
