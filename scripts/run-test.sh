#!/bin/bash

set -ex

gcc -g -o ./goo-test       \
  -lgmp -lcrypto           \
  -std=c89                 \
  -pedantic                \
  -Wcast-align             \
  -Wshadow                 \
  -Wno-long-long           \
  -Wno-overlength-strings  \
  -O3                      \
  -DGOO_HAS_GMP            \
  -DGOO_HAS_CRYPTO         \
  ./src/goo/drbg.c         \
  ./src/goo/hmac.c         \
  ./src/goo/mini-gmp.c     \
  ./src/goo/sha256.c       \
  ./src/goo/test.c

./goo-test

valgrind                \
  --tool=memcheck       \
  --leak-check=full     \
  --show-leak-kinds=all \
  --error-limit=no      \
  ./goo-test

rm ./goo-test
