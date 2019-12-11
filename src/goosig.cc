/*!
 * goosig.cc - groups of unknown order for C
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#include "goosig.h"
#include "random.h"

NAN_INLINE static bool
IsNull(v8::Local<v8::Value> obj) {
  Nan::HandleScope scope;
  return obj->IsNull() || obj->IsUndefined();
}

static Nan::Persistent<v8::FunctionTemplate> goosig_constructor;

Goo::Goo() {}

Goo::~Goo() {
  goo_uninit(&ctx);
}

void
Goo::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(Goo::New);

  goosig_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("Goo").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "generate", Goo::Generate);
  Nan::SetPrototypeMethod(tpl, "challenge", Goo::Challenge);
  Nan::SetPrototypeMethod(tpl, "validate", Goo::Validate);
  Nan::SetPrototypeMethod(tpl, "sign", Goo::Sign);
  Nan::SetPrototypeMethod(tpl, "verify", Goo::Verify);
#ifdef GOO_TEST
  Nan::SetMethod(tpl, "test", Goo::Test);
#endif

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(goosig_constructor);

  Nan::Set(target, Nan::New("Goo").ToLocalChecked(),
    Nan::GetFunction(ctor).ToLocalChecked());
}

NAN_METHOD(Goo::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create Goo instance.");

  if (info.Length() < 3)
    return Nan::ThrowError("Goo requires arguments.");

  v8::Local<v8::Object> n_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(n_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  if (!info[1]->IsNumber())
    return Nan::ThrowTypeError("Second argument must be a number.");

  if (!info[2]->IsNumber())
    return Nan::ThrowTypeError("Third argument must be a number.");

  const uint8_t *n = (const uint8_t *)node::Buffer::Data(n_buf);
  size_t n_len = node::Buffer::Length(n_buf);
  unsigned long g = (unsigned long)Nan::To<int64_t>(info[1]).FromJust();
  unsigned long h = (unsigned long)Nan::To<int64_t>(info[2]).FromJust();

  unsigned long modbits = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsNumber())
      return Nan::ThrowTypeError("Fourth argument must be a number.");

    modbits = (unsigned long)Nan::To<int64_t>(info[3]).FromJust();
  }

  Goo *goo = new Goo();

  goo->Wrap(info.This());

  if (!goo_init(&goo->ctx, n, n_len, g, h, modbits))
    return Nan::ThrowError("Could not initialize context.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Goo::Generate) {
  unsigned char s_prime[32];

  if (!goo_random((void *)&s_prime[0], 32))
    return Nan::ThrowError("Could not generate s_prime.");

  info.GetReturnValue().Set(
    Nan::CopyBuffer((char *)s_prime, 32).ToLocalChecked());
}

NAN_METHOD(Goo::Challenge) {
  Goo *goo = ObjectWrap::Unwrap<Goo>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("goo.challenge() requires arguments.");

  v8::Local<v8::Object> s_prime_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(s_prime_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Object> n_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(n_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *s_prime = (const uint8_t *)node::Buffer::Data(s_prime_buf);
  size_t s_prime_len = node::Buffer::Length(s_prime_buf);

  const uint8_t *n = (const uint8_t *)node::Buffer::Data(n_buf);
  size_t n_len = node::Buffer::Length(n_buf);

  unsigned char *C1;
  size_t C1_len;

  if (s_prime_len != 32)
    return Nan::ThrowRangeError("s_prime must be 32 bytes.");

  if (!goo_challenge(&goo->ctx, &C1, &C1_len, s_prime, n, n_len))
    return Nan::ThrowError("Could not create challenge.");

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)C1, C1_len).ToLocalChecked());
}

NAN_METHOD(Goo::Validate) {
  Goo *goo = ObjectWrap::Unwrap<Goo>(info.Holder());

  if (info.Length() < 4)
    return Nan::ThrowError("goo.validate() requires arguments.");

  v8::Local<v8::Object> s_prime_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(s_prime_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> C1_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(C1_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Value> p_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(p_buf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Value> q_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(q_buf))
    return Nan::ThrowTypeError("Fourth argument must be a buffer.");

  const uint8_t *s_prime = (const uint8_t *)node::Buffer::Data(s_prime_buf);
  size_t s_prime_len = node::Buffer::Length(s_prime_buf);

  const uint8_t *C1 = (const uint8_t *)node::Buffer::Data(C1_buf);
  size_t C1_len = node::Buffer::Length(C1_buf);

  const uint8_t *p = (const uint8_t *)node::Buffer::Data(p_buf);
  size_t p_len = node::Buffer::Length(p_buf);

  const uint8_t *q = (const uint8_t *)node::Buffer::Data(q_buf);
  size_t q_len = node::Buffer::Length(q_buf);

  if (s_prime_len != 32)
    return Nan::ThrowRangeError("s_prime must be 32 bytes.");

  int result = goo_validate(&goo->ctx, s_prime, C1, C1_len, p, p_len, q, q_len);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_METHOD(Goo::Sign) {
  Goo *goo = ObjectWrap::Unwrap<Goo>(info.Holder());

  if (info.Length() < 4)
    return Nan::ThrowError("goo.sign() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> s_prime_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(s_prime_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Value> p_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(p_buf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Value> q_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(q_buf))
    return Nan::ThrowTypeError("Fourth argument must be a buffer.");

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  const uint8_t *s_prime = (const uint8_t *)node::Buffer::Data(s_prime_buf);
  size_t s_prime_len = node::Buffer::Length(s_prime_buf);

  const uint8_t *p = (const uint8_t *)node::Buffer::Data(p_buf);
  size_t p_len = node::Buffer::Length(p_buf);

  const uint8_t *q = (const uint8_t *)node::Buffer::Data(q_buf);
  size_t q_len = node::Buffer::Length(q_buf);

  unsigned char *sig;
  size_t sig_len;

  if (s_prime_len != 32)
    return Nan::ThrowRangeError("s_prime must be 32 bytes.");

  uint8_t seed[64];

  if (!goo_random((void *)&seed[0], 64))
    return Nan::ThrowError("Could not seed RNG.");

  if (!goo_sign(&goo->ctx,
                &sig, &sig_len,
                msg, msg_len,
                s_prime,
                p, p_len,
                q, q_len,
                &seed[0])) {
    return Nan::ThrowError("Could create signature.");
  }

  info.GetReturnValue().Set(
    Nan::NewBuffer((char *)sig, sig_len).ToLocalChecked());
}

NAN_METHOD(Goo::Verify) {
  Goo *goo = ObjectWrap::Unwrap<Goo>(info.Holder());

  if (info.Length() < 3)
    return Nan::ThrowError("goo.verify() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> sig_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(sig_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Value> C1_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(C1_buf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  const uint8_t *sig = (const uint8_t *)node::Buffer::Data(sig_buf);
  size_t sig_len = node::Buffer::Length(sig_buf);

  const uint8_t *C1 = (const uint8_t *)node::Buffer::Data(C1_buf);
  size_t C1_len = node::Buffer::Length(C1_buf);

  int result = goo_verify(&goo->ctx, msg, msg_len,
                          sig, sig_len, C1, C1_len);

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

#ifdef GOO_TEST
NAN_METHOD(Goo::Test) {
  goo_test();
  return info.GetReturnValue().Set(Nan::Null());
}
#endif

NAN_MODULE_INIT(init) {
  Goo::Init(target);
}

#if NODE_MAJOR_VERSION >= 10
NAN_MODULE_WORKER_ENABLED(goo, init)
#else
NODE_MODULE(goo, init)
#endif
