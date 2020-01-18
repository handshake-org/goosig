/*!
 * sha256.c - sha256 for C89
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/SHA-2
 *   https://tools.ietf.org/html/rfc4634
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sha256.h"

static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const unsigned char P[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static void
write32(void *dst, uint32_t w);

static void
write64(void *dst, uint64_t w);

static uint32_t
read32(const void *src);

void
goo_sha256_init(goo_sha256_t *ctx) {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->size = 0;
}

static void
goo_sha256_transform(goo_sha256_t *ctx, const unsigned char *chunk) {
  uint32_t W[64];
  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];
  uint32_t f = ctx->state[5];
  uint32_t g = ctx->state[6];
  uint32_t h = ctx->state[7];
  uint32_t t1, t2;
  size_t i = 0;

#define Sigma0(x) \
  ((x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10))
#define Sigma1(x) \
  ((x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7))
#define sigma0(x) ((x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3))
#define sigma1(x) ((x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10))
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#define Maj(x, y, z) ((x & y) | (z & (x | y)))

  for (; i < 16; i++)
    W[i] = read32(chunk + i * 4);

  for (; i < 64; i++)
    W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];

  for (i = 0; i < 64; i++) {
    t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
    t2 = Sigma0(a) + Maj(a, b, c);

    h = g;
    g = f;
    f = e;

    e = d + t1;

    d = c;
    c = b;
    b = a;

    a = t1 + t2;
  }

#undef Sigma0
#undef Sigma1
#undef sigma0
#undef sigma1
#undef Ch
#undef Maj

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

void
goo_sha256_update(goo_sha256_t *ctx, const void *data, size_t len) {
  const unsigned char *bytes = (const unsigned char *)data;
  size_t pos = ctx->size & 63;
  size_t off = 0;

  ctx->size += len;

  if (pos > 0) {
    size_t want = 64 - pos;

    if (want > len)
      want = len;

    memcpy(ctx->block + pos, bytes + off, want);

    pos += want;
    len -= want;
    off += want;

    if (pos < 64)
      return;

    goo_sha256_transform(ctx, ctx->block);
  }

  while (len >= 64) {
    goo_sha256_transform(ctx, bytes + off);
    off += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(ctx->block, bytes + off, len);
}

void
goo_sha256_final(goo_sha256_t *ctx, unsigned char *out) {
  size_t pos = ctx->size & 63;
  uint64_t len = ctx->size << 3;
  unsigned char D[8];
  size_t i;

  write64(D, len);

  goo_sha256_update(ctx, P, 1 + ((119 - pos) & 63));
  goo_sha256_update(ctx, D, 8);

  for (i = 0; i < 8; i++)
    write32(out + i * 4, ctx->state[i]);

  memset(ctx->state, 0x00, sizeof(ctx->state));
  memset(ctx->block, 0x00, sizeof(ctx->block));

  ctx->size = 0;
}

void
goo_sha256(unsigned char *out, const void *data, size_t len) {
  goo_sha256_t ctx;
  goo_sha256_init(&ctx);
  goo_sha256_update(&ctx, data, len);
  goo_sha256_final(&ctx, out);
}

static uint32_t
read32(const void *src) {
#ifdef WORDS_BIGENDIAN
  uint32_t w;
  memcpy(&w, src, sizeof(w));
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)p[0] << 24)
       | ((uint32_t)p[1] << 16)
       | ((uint32_t)p[2] << 8)
       | ((uint32_t)p[3] << 0);
#endif
}

static void
write32(void *dst, uint32_t w) {
#ifdef WORDS_BIGENDIAN
  memcpy(dst, &w, sizeof(w));
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = w >> 24;
  p[1] = w >> 16;
  p[2] = w >> 8;
  p[3] = w >> 0;
#endif
}

static void
write64(void *dst, uint64_t w) {
#ifdef WORDS_BIGENDIAN
  memcpy(dst, &w, sizeof(w));
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = w >> 56;
  p[1] = w >> 48;
  p[2] = w >> 40;
  p[3] = w >> 32;
  p[4] = w >> 24;
  p[5] = w >> 16;
  p[6] = w >> 8;
  p[7] = w >> 0;
#endif
}
