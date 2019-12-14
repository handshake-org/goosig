/*!
 * chacha20.c - chacha20 for C89
 * Copyright (c) 2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Chacha20
 *   https://tools.ietf.org/html/rfc7539#section-2
 *   https://cr.yp.to/chacha.html
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "chacha20.h"

#define ROTL32(x, y) ((x) << (y)) | ((x) >> (32 - (y)))

#define QROUND(x, a, b, c, d)                   \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8);  \
  x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7)

static uint32_t
read32(const void *src);

static void
write32(void *dst, uint32_t w);

static void
goo_chacha20_block(goo_chacha20_t *ctx);

void
goo_chacha20_init(goo_chacha20_t *ctx,
                  const unsigned char *key32,
                  const unsigned char *nonce24) {
  uint8_t key[32];
  const uint8_t *nonce16 = &nonce24[0];
  const uint8_t *nonce8 = &nonce24[16];

  goo_chacha20_derive(key, key32, nonce16);

  ctx->state[0] = 0x61707865;
  ctx->state[1] = 0x3320646e;
  ctx->state[2] = 0x79622d32;
  ctx->state[3] = 0x6b206574;
  ctx->state[4] = read32(&key[0]);
  ctx->state[5] = read32(&key[4]);
  ctx->state[6] = read32(&key[8]);
  ctx->state[7] = read32(&key[12]);
  ctx->state[8] = read32(&key[16]);
  ctx->state[9] = read32(&key[20]);
  ctx->state[10] = read32(&key[24]);
  ctx->state[11] = read32(&key[28]);
  ctx->state[12] = 0;
  ctx->state[13] = 0;
  ctx->state[14] = read32(nonce8 + 0);
  ctx->state[15] = read32(nonce8 + 4);

  ctx->pos = 0;
}

void
goo_chacha20_encrypt(goo_chacha20_t *ctx,
                     unsigned char *out,
                     const unsigned char *data,
                     size_t len) {
  uint8_t *stream = &ctx->stream.bytes[0];
  size_t i;

  for (i = 0; i < len; i++) {
    if ((ctx->pos & 63) == 0) {
      goo_chacha20_block(ctx);
      ctx->pos = 0;
    }

    out[i] = data[i] ^ stream[ctx->pos++];
  }
}

static void
goo_chacha20_block(goo_chacha20_t *ctx) {
  uint32_t *stream = &ctx->stream.ints[0];
#ifdef GOO_USE_ASM
  /* Borrowed from:
   * https://github.com/gnutls/nettle/blob/master/x86_64/chacha-core-internal.asm
   *
   * Layout:
   *   %rsi = src pointer (&ctx->state[0])
   *   %rdi = dst pointer (&stream[0])
   *   %edx = rounds integer (nettle does `20 >> 1`)
   *
   * For reference, our full range of clobbered registers:
   * rsi, rdi, edx
   */
  __asm__ __volatile__(
    "movq %[src], %%rsi\n"
    "movq %[dst], %%rdi\n"
    "movl $20, %%edx\n"

    "movups (%%rsi), %%xmm0\n"
    "movups 16(%%rsi), %%xmm1\n"
    "movups 32(%%rsi), %%xmm2\n"
    "movups 48(%%rsi), %%xmm3\n"

    "shrl $1, %%edx\n"

    "1:\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"

    "pshufhw $0xb1, %%xmm3, %%xmm3\n"
    "pshuflw $0xb1, %%xmm3, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $12, %%xmm1\n"
    "psrld $20, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"
    "pslld $8, %%xmm3\n"
    "psrld $24, %%xmm4\n"
    "por %%xmm4, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $7, %%xmm1\n"
    "psrld $25, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "pshufd $0x39, %%xmm1, %%xmm1\n"
    "pshufd $0x4e, %%xmm2, %%xmm2\n"
    "pshufd $0x93, %%xmm3, %%xmm3\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"

    "pshufhw $0xb1, %%xmm3, %%xmm3\n"
    "pshuflw $0xb1, %%xmm3, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $12, %%xmm1\n"
    "psrld $20, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "paddd %%xmm1, %%xmm0\n"
    "pxor %%xmm0, %%xmm3\n"
    "movaps %%xmm3, %%xmm4\n"
    "pslld $8, %%xmm3\n"
    "psrld $24, %%xmm4\n"
    "por %%xmm4, %%xmm3\n"

    "paddd %%xmm3, %%xmm2\n"
    "pxor %%xmm2, %%xmm1\n"
    "movaps %%xmm1, %%xmm4\n"
    "pslld $7, %%xmm1\n"
    "psrld $25, %%xmm4\n"
    "por %%xmm4, %%xmm1\n"

    "pshufd $0x93, %%xmm1, %%xmm1\n"
    "pshufd $0x4e, %%xmm2, %%xmm2\n"
    "pshufd $0x39, %%xmm3, %%xmm3\n"

    "decl %%edx\n"
    "jnz 1b\n"

    "movups (%%rsi), %%xmm4\n"
    "movups 16(%%rsi), %%xmm5\n"
    "paddd %%xmm4, %%xmm0\n"
    "paddd %%xmm5, %%xmm1\n"
    "movups %%xmm0,(%%rdi)\n"
    "movups %%xmm1,16(%%rdi)\n"
    "movups 32(%%rsi), %%xmm4\n"
    "movups 48(%%rsi), %%xmm5\n"
    "paddd %%xmm4, %%xmm2\n"
    "paddd %%xmm5, %%xmm3\n"
    "movups %%xmm2,32(%%rdi)\n"
    "movups %%xmm3,48(%%rdi)\n"

    "incq 48(%%rsi)\n"
    :
    : [src] "r" (ctx->state),
      [dst] "r" (stream)
    : "rsi", "rdi", "edx", "cc", "memory"
  );
#else
  int i;

  memcpy(stream, &ctx->state[0], sizeof(ctx->state));

  for (i = 0; i < 10; i++) {
    QROUND(stream, 0, 4, 8, 12);
    QROUND(stream, 1, 5, 9, 13);
    QROUND(stream, 2, 6, 10, 14);
    QROUND(stream, 3, 7, 11, 15);
    QROUND(stream, 0, 5, 10, 15);
    QROUND(stream, 1, 6, 11, 12);
    QROUND(stream, 2, 7, 8, 13);
    QROUND(stream, 3, 4, 9, 14);
  }

  for (i = 0; i < 16; i++)
    stream[i] += ctx->state[i];

#ifdef WORDS_BIGENDIAN
  uint8_t *bytes = &ctx->stream.bytes[0];

  for (i = 0; i < 16; i++)
    write32(bytes + i * 4, stream[i]);
#endif

  ctx->state[12] += 1;

  if (ctx->state[12] == 0)
    ctx->state[13] += 1;
#endif
}

void
goo_chacha20_derive(unsigned char *out,
                    const unsigned char *key32,
                    const unsigned char *nonce16) {
  uint32_t state[16];
  int i;

  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  state[4] = read32(key32 + 0);
  state[5] = read32(key32 + 4);
  state[6] = read32(key32 + 8);
  state[7] = read32(key32 + 12);
  state[8] = read32(key32 + 16);
  state[9] = read32(key32 + 20);
  state[10] = read32(key32 + 24);
  state[11] = read32(key32 + 28);
  state[12] = read32(nonce16 + 0);
  state[13] = read32(nonce16 + 4);
  state[14] = read32(nonce16 + 8);
  state[15] = read32(nonce16 + 12);

  for (i = 0; i < 10; i++) {
    QROUND(state, 0, 4, 8, 12);
    QROUND(state, 1, 5, 9, 13);
    QROUND(state, 2, 6, 10, 14);
    QROUND(state, 3, 7, 11, 15);
    QROUND(state, 0, 5, 10, 15);
    QROUND(state, 1, 6, 11, 12);
    QROUND(state, 2, 7, 8, 13);
    QROUND(state, 3, 4, 9, 14);
  }

  write32(out + 0, state[0]);
  write32(out + 4, state[1]);
  write32(out + 8, state[2]);
  write32(out + 12, state[3]);
  write32(out + 16, state[12]);
  write32(out + 20, state[13]);
  write32(out + 24, state[14]);
  write32(out + 28, state[15]);
}

static uint32_t
read32(const void *src) {
#ifndef WORDS_BIGENDIAN
  uint32_t w;
  memcpy((void *)&w, src, sizeof(w));
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)(p[0]) << 0)
       | ((uint32_t)(p[1]) << 8)
       | ((uint32_t)(p[2]) << 16)
       | ((uint32_t)(p[3]) << 24);
#endif
}

static void
write32(void *dst, uint32_t w) {
#ifndef WORDS_BIGENDIAN
  memcpy(dst, (void *)&w, sizeof(w));
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = w >> 0;
  p[1] = w >> 8;
  p[2] = w >> 16;
  p[3] = w >> 24;
#endif
}
