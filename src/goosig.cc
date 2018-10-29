#include "goosig.h"

static Nan::Persistent<v8::FunctionTemplate> goosig_constructor;

GooVerifier::GooVerifier() {}

GooVerifier::~GooVerifier() {
  goo_uninit(&ctx);
}

void
GooVerifier::Init(v8::Local<v8::Object> &target) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl =
    Nan::New<v8::FunctionTemplate>(GooVerifier::New);

  goosig_constructor.Reset(tpl);

  tpl->SetClassName(Nan::New("GooVerifier").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "verify", GooVerifier::Verify);

  v8::Local<v8::FunctionTemplate> ctor =
    Nan::New<v8::FunctionTemplate>(goosig_constructor);

  target->Set(Nan::New("GooVerifier").ToLocalChecked(), ctor->GetFunction());
}

NAN_METHOD(GooVerifier::New) {
  if (!info.IsConstructCall())
    return Nan::ThrowError("Could not create GooVerifier instance.");

  if (info.Length() < 3)
    return Nan::ThrowError("GooVerifier requires arguments.");

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

  GooVerifier *goosig = new GooVerifier();

  goosig->Wrap(info.This());

  if (!goo_init(&goosig->ctx, n, n_len, g, h))
    return Nan::ThrowError("Could not initialize context.");

  info.GetReturnValue().Set(info.This());
}

NAN_METHOD(GooVerifier::Verify) {
  GooVerifier *goosig = ObjectWrap::Unwrap<GooVerifier>(info.Holder());

  if (info.Length() < 2)
    return Nan::ThrowError("goosig.verify() requires arguments.");

  v8::Local<v8::Object> msg_buf = info[0].As<v8::Object>();

  if (!node::Buffer::HasInstance(msg_buf))
    return Nan::ThrowTypeError("First argument must be a buffer.");

  v8::Local<v8::Value> proof_buf = info[1].As<v8::Object>();

  if (!node::Buffer::HasInstance(proof_buf))
    return Nan::ThrowTypeError("Second argument must be a buffer.");

  const uint8_t *msg = (const uint8_t *)node::Buffer::Data(msg_buf);
  size_t msg_len = node::Buffer::Length(msg_buf);

  const uint8_t *proof = (const uint8_t *)node::Buffer::Data(proof_buf);
  size_t proof_len = node::Buffer::Length(proof_buf);

  bool result = goo_verify(&goosig->ctx, msg, msg_len, proof, proof_len) == 1;

  return info.GetReturnValue().Set(Nan::New<v8::Boolean>(result));
}

NAN_MODULE_INIT(init) {
  GooVerifier::Init(target);
}

NODE_MODULE(goosig, init)
