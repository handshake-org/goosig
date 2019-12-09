/*!
 * random.c - random number generation for C
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#include <assert.h>
#include <stdlib.h>
#include "openssl/rand.h"
#include "random.h"

void
goo_poll(void) {
  for (;;) {
    /* https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/rand_lib.c#L792 */
    /* https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/drbg_lib.c#L988 */
    int status = RAND_status();

    assert(status >= 0);

    if (status != 0)
      break;

    /* https://github.com/openssl/openssl/blob/bc420eb/crypto/rand/rand_lib.c#L376 */
    /* https://github.com/openssl/openssl/blob/32f803d/crypto/rand/drbg_lib.c#L471 */
    if (RAND_poll() == 0)
      break;
  }
}

int
goo_random(void *dst, size_t len) {
  int r;

  goo_poll();

  r = RAND_bytes(dst, len);

  if (r != 1)
    return 0;

  return 1;
}
