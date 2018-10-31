#include "goosig.h"

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

  Nan::SetPrototypeMethod(tpl, "challenge", Goo::Challenge);
  Nan::SetPrototypeMethod(tpl, "sign", Goo::Sign);
  Nan::SetPrototypeMethod(tpl, "verify", Goo::Verify);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(goosig_constructor);

  target->Set(Nan::New("Goo").ToLocalChecked(), ctor->GetFunction());
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
  unsigned long g = (unsigned long)info[1]->IntegerValue();
  unsigned long h = (unsigned long)info[2]->IntegerValue();

  unsigned long modbits = 0;

  if (info.Length() > 3 && !IsNull(info[3])) {
    if (!info[3]->IsNumber())
      return Nan::ThrowTypeError("Fourth argument must be a number.");

    modbits = (unsigned long)info[3]->IntegerValue();
  }

  Goo *goo = new Goo();

  goo->Wrap(info.This());

  if (!goo_init(&goo->ctx, n, n_len, g, h, modbits))
    return Nan::ThrowError("Could not initialize context.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(Goo::Challenge) {
  Goo *goo = ObjectWrap::Unwrap<Goo>(info.Holder());

  if (info.Length() < 1)
    return Nan::ThrowError("goo.challenge() requires arguments.");

  v8::Local<v8::Object> n_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(n_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  const uint8_t *n = (const uint8_t *)node::Buffer::Data(n_buf);
  size_t n_len = node::Buffer::Length(n_buf);

  unsigned char *s_prime;
  size_t s_prime_len;

  unsigned char *C1;
  size_t C1_len;

  if (!goo_challenge(&goo->ctx,
                     &s_prime, &s_prime_len,
                     &C1, &C1_len, n, n_len)) {
    return Nan::ThrowError("Could create challenge.");
  }

  v8::Local<v8::Array> ret = Nan::New<v8::Array>();
  ret->Set(0, Nan::NewBuffer((char *)s_prime, s_prime_len).ToLocalChecked());
  ret->Set(1, Nan::NewBuffer((char *)C1, C1_len).ToLocalChecked());

  return info.GetReturnValue().Set(ret);
}

NAN_METHOD(Goo::Sign) {
  Goo *goo = ObjectWrap::Unwrap<Goo>(info.Holder());

  if (info.Length() < 6)
    return Nan::ThrowError("goo.sign() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> s_prime_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(s_prime_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  v8::Local<v8::Value> C1_buf = info[2].As<v8::Object>();

  if (!node::Buffer::HasInstance(C1_buf))
    return Nan::ThrowTypeError("Third argument must be a buffer.");

  v8::Local<v8::Value> n_buf = info[3].As<v8::Object>();

  if (!node::Buffer::HasInstance(n_buf))
    return Nan::ThrowTypeError("Fourth argument must be a buffer.");

  v8::Local<v8::Value> p_buf = info[4].As<v8::Object>();

  if (!node::Buffer::HasInstance(p_buf))
    return Nan::ThrowTypeError("Fifth argument must be a buffer.");

  v8::Local<v8::Value> q_buf = info[5].As<v8::Object>();

  if (!node::Buffer::HasInstance(q_buf))
    return Nan::ThrowTypeError("Sixth argument must be a buffer.");

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  const uint8_t *s_prime = (const uint8_t *)node::Buffer::Data(s_prime_buf);
  size_t s_prime_len = node::Buffer::Length(s_prime_buf);

  const uint8_t *C1 = (const uint8_t *)node::Buffer::Data(C1_buf);
  size_t C1_len = node::Buffer::Length(C1_buf);

  const uint8_t *n = (const uint8_t *)node::Buffer::Data(n_buf);
  size_t n_len = node::Buffer::Length(n_buf);

  const uint8_t *p = (const uint8_t *)node::Buffer::Data(p_buf);
  size_t p_len = node::Buffer::Length(p_buf);

  const uint8_t *q = (const uint8_t *)node::Buffer::Data(q_buf);
  size_t q_len = node::Buffer::Length(q_buf);

  unsigned char *sig;
  size_t sig_len;

  if (!goo_sign(&goo->ctx,
                &sig, &sig_len,
                msg, msg_len,
                s_prime, s_prime_len,
                C1, C1_len,
                n, n_len,
                p, p_len,
                q, q_len)) {
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

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result == 1));
}

NAN_MODULE_INIT(init) {
  Goo::Init(target);
}

NODE_MODULE(goo, init)
