/*!
 * goosig.cc - groups of unknown order
 * Copyright (c) 2018-2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <node_api.h>
#include "goo/goo.h"

#define CHECK(expr) do {                               \
  if (!(expr)) {                                       \
    fprintf(stderr, "%s:%d: Assertion `%s' failed.\n", \
            __FILE__, __LINE__, #expr);                \
    fflush(stderr);                                    \
    abort();                                           \
  }                                                    \
} while (0)

#define JS_THROW(msg) do {                              \
  CHECK(napi_throw_error(env, NULL, (msg)) == napi_ok); \
  return NULL;                                          \
} while (0)

#define JS_ASSERT(cond, msg) if (!(cond)) JS_THROW(msg)

#define JS_ERR_CONTEXT "Could not create context."
#define JS_ERR_ENTROPY_SIZE "Invalid entropy size."
#define JS_ERR_SPRIME_SIZE "Invalid s_prime size."
#define JS_ERR_GENERATE "Could not generate s_prime."
#define JS_ERR_CHALLENGE "Could not create challenge."
#define JS_ERR_SIGN "Could not sign."

/*
 * N-API Extras
 */

static void
finalize_buffer(napi_env env, void *data, void *hint) {
  if (data != NULL)
    free(data);
}

static napi_status
create_external_buffer(napi_env env, size_t length,
                       void *data, napi_value *result) {
  return napi_create_external_buffer(env,
                                     length,
                                     data,
                                     finalize_buffer,
                                     NULL,
                                     result);
}

/*
 * GooSig
 */

static void
goosig_destroy(napi_env env, void *data, void *hint) {
  goo_ctx_t *goo = (goo_ctx_t *)data;
  goo_destroy(goo);
}

static napi_value
goosig_create(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *n;
  size_t n_len;
  uint32_t g, h, bits;
  goo_ctx_t *goo;
  napi_value handle;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&n, &n_len) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[1], &g) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[2], &h) == napi_ok);
  CHECK(napi_get_value_uint32(env, argv[3], &bits) == napi_ok);

  goo = goo_create(n, n_len, g, h, bits);

  JS_ASSERT(goo != NULL, JS_ERR_CONTEXT);

  CHECK(napi_create_external(env,
                             goo,
                             goosig_destroy,
                             NULL,
                             &handle) == napi_ok);

  return handle;
}

static napi_value
goosig_generate(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  size_t argc = 1;
  uint8_t out[32];
  const uint8_t *entropy;
  size_t entropy_len;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 1);
  CHECK(napi_get_buffer_info(env, argv[0], (void **)&entropy,
                             &entropy_len) == napi_ok);

  JS_ASSERT(entropy_len == 32, JS_ERR_ENTROPY_SIZE);
  JS_ASSERT(goo_generate(NULL, out, entropy), JS_ERR_GENERATE);

  CHECK(napi_create_buffer_copy(env, 32, out, NULL, &result) == napi_ok);

  return result;
}

static napi_value
goosig_challenge(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  size_t argc = 3;
  uint8_t *out;
  size_t out_len;
  const uint8_t *s_prime, *n;
  size_t s_prime_len, n_len;
  goo_ctx_t *goo;
  napi_value result;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 3);
  CHECK(napi_get_value_external(env, argv[0], (void **)&goo) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&s_prime,
                             &s_prime_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&n, &n_len) == napi_ok);

  JS_ASSERT(s_prime_len == 32, JS_ERR_SPRIME_SIZE);
  JS_ASSERT(goo_challenge(goo, &out, &out_len, s_prime, n, n_len),
            JS_ERR_CHALLENGE);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
goosig_validate(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  const uint8_t *s_prime, *C1, *p, *q;
  size_t s_prime_len, C1_len, p_len, q_len;
  goo_ctx_t *goo;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&goo) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&s_prime,
                             &s_prime_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&C1, &C1_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&p, &p_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&q, &q_len) == napi_ok);

  JS_ASSERT(s_prime_len == 32, JS_ERR_SPRIME_SIZE);

  ok = goo_validate(goo, s_prime, C1, C1_len, p, p_len, q, q_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

static napi_value
goosig_sign(napi_env env, napi_callback_info info) {
  napi_value argv[5];
  size_t argc = 5;
  uint8_t *out;
  size_t out_len;
  const uint8_t *msg, *s_prime, *p, *q;
  size_t msg_len, s_prime_len, p_len, q_len;
  goo_ctx_t *goo;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 5);
  CHECK(napi_get_value_external(env, argv[0], (void **)&goo) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg, &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&s_prime,
                             &s_prime_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&p, &p_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[4], (void **)&q, &q_len) == napi_ok);

  JS_ASSERT(s_prime_len == 32, JS_ERR_SPRIME_SIZE);

  ok = goo_sign(goo, &out, &out_len, msg, msg_len, s_prime, p, p_len, q, q_len);

  JS_ASSERT(ok, JS_ERR_SIGN);

  CHECK(create_external_buffer(env, out_len, out, &result) == napi_ok);

  return result;
}

static napi_value
goosig_verify(napi_env env, napi_callback_info info) {
  napi_value argv[4];
  size_t argc = 4;
  const uint8_t *msg, *sig, *C1;
  size_t msg_len, sig_len, C1_len;
  goo_ctx_t *goo;
  napi_value result;
  int ok;

  CHECK(napi_get_cb_info(env, info, &argc, argv, NULL, NULL) == napi_ok);
  CHECK(argc == 4);
  CHECK(napi_get_value_external(env, argv[0], (void **)&goo) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[1], (void **)&msg,
                             &msg_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[2], (void **)&sig, &sig_len) == napi_ok);
  CHECK(napi_get_buffer_info(env, argv[3], (void **)&C1, &C1_len) == napi_ok);

  ok = goo_verify(goo, msg, msg_len, sig, sig_len, C1, C1_len);

  CHECK(napi_get_boolean(env, ok, &result) == napi_ok);

  return result;
}

/*
 * Module
 */

napi_value
goosig_init(napi_env env, napi_value exports) {
  size_t i;

  static struct {
    const char *name;
    napi_callback callback;
  } funcs[] = {
    { "goosig_create", goosig_create },
    { "goosig_generate", goosig_generate },
    { "goosig_challenge", goosig_challenge },
    { "goosig_validate", goosig_validate },
    { "goosig_sign", goosig_sign },
    { "goosig_verify", goosig_verify }
  };

  for (i = 0; i < sizeof(funcs) / sizeof(funcs[0]); i++) {
    const char *name = funcs[i].name;
    napi_callback callback = funcs[i].callback;
    napi_value fn;

    CHECK(napi_create_function(env,
                               name,
                               NAPI_AUTO_LENGTH,
                               callback,
                               NULL,
                               &fn) == napi_ok);

    CHECK(napi_set_named_property(env, exports, name, fn) == napi_ok);
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, goosig_init)
