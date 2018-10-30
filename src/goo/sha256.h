#ifndef _GOO_SHA256_H
#define _GOO_SHA256_H

#include <stdlib.h>
#include "openssl/sha.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define GOO_HASH_SIZE 32
#define GOO_BLOCK_SIZE 64

typedef SHA256_CTX goo_sha256_t;

static inline void
goo_sha256_init(goo_sha256_t *ctx) {
  SHA256_Init(ctx);
}

static inline void
goo_sha256_update(goo_sha256_t *ctx, const unsigned char *data, size_t len) {
  SHA256_Update(ctx, data, len);
}

static inline void
goo_sha256_final(goo_sha256_t *ctx, unsigned char *out) {
  SHA256_Final(out, ctx);
}

static inline void
goo_sha256(unsigned char *out, const unsigned char *data, size_t len) {
  SHA256(data, len, out);
}

#if defined(__cplusplus)
}
#endif

#endif
