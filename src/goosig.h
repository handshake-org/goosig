#ifndef _GOOSIG_HH
#define _GOOSIG_HH

#include <node.h>
#include <nan.h>

#include "goo/goo.h"

class GooVerifier : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  GooVerifier();
  ~GooVerifier();

  goo_ctx_t ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Verify);
};
#endif

