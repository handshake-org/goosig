/*!
 * goo.c - groups of unknown order for C89
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#ifndef _GOO_H
#define _GOO_H

#include <stdlib.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct goo_group_s goo_ctx_t;

goo_ctx_t *
goo_create(const unsigned char *n,
           size_t n_len,
           unsigned long g,
           unsigned long h,
           unsigned long bits);

void
goo_destroy(goo_ctx_t *ctx);

int
goo_generate(goo_ctx_t *ctx,
             unsigned char *s_prime,
             const unsigned char *entropy);

int
goo_challenge(goo_ctx_t *ctx,
              unsigned char **C1,
              size_t *C1_len,
              const unsigned char *s_prime,
              const unsigned char *n,
              size_t n_len);

int
goo_validate(goo_ctx_t *ctx,
             const unsigned char *s_prime,
             const unsigned char *C1,
             size_t C1_len,
             const unsigned char *p,
             size_t p_len,
             const unsigned char *q,
             size_t q_len);

int
goo_sign(goo_ctx_t *ctx,
         unsigned char **out,
         size_t *out_len,
         const unsigned char *msg,
         size_t msg_len,
         const unsigned char *s_prime,
         const unsigned char *p,
         size_t p_len,
         const unsigned char *q,
         size_t q_len);

int
goo_verify(goo_ctx_t *ctx,
           const unsigned char *msg,
           size_t msg_len,
           const unsigned char *sig,
           size_t sig_len,
           const unsigned char *C1,
           size_t C1_len);

int
goo_encrypt(goo_ctx_t *ctx,
            unsigned char **out,
            size_t *out_len,
            const unsigned char *msg,
            size_t msg_len,
            const unsigned char *n,
            size_t n_len,
            const unsigned char *e,
            size_t e_len,
            const unsigned char *label,
            size_t label_len,
            const unsigned char *entropy);

int
goo_decrypt(goo_ctx_t *ctx,
            unsigned char **out,
            size_t *out_len,
            const unsigned char *msg,
            size_t msg_len,
            const unsigned char *p,
            size_t p_len,
            const unsigned char *q,
            size_t q_len,
            const unsigned char *e,
            size_t e_len,
            const unsigned char *label,
            size_t label_len,
            const unsigned char *entropy);

/**
 * Moduli of unknown factorization.
 */

/* America Online Root CA 1 (2048) */
extern const unsigned char GOO_AOL1[256];

/* America Online Root CA 2 (4096) */
extern const unsigned char GOO_AOL2[512];

/* RSA-2048 Factoring Challenge (2048) */
extern const unsigned char GOO_RSA2048[256];

/* RSA-617 Factoring Challenge (2048) */
extern const unsigned char GOO_RSA617[256];

#if defined(__cplusplus)
}
#endif

#endif
