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
