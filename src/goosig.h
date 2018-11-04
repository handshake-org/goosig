/*!
 * goosig.cc - groups of unknown order for C
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/goosig
 */

#ifndef _GOOSIG_HH
#define _GOOSIG_HH

#include <node.h>
#include <nan.h>

#include "goo/goo.h"

class Goo : public Nan::ObjectWrap {
public:
  static NAN_METHOD(New);
  static void Init(v8::Local<v8::Object> &target);

  Goo();
  ~Goo();

  goo_ctx_t ctx;

private:
  static NAN_METHOD(Init);
  static NAN_METHOD(Challenge);
  static NAN_METHOD(Sign);
  static NAN_METHOD(Verify);
#ifdef GOO_TEST
  static NAN_METHOD(Test);
#endif
};
#endif

