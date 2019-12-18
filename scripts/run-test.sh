#!/bin/bash

set -ex

for cc in gcc clang; do
  if test x"$1" = x'--full'; then
    "$cc" -g -o ./goo-test     \
      -std=c89                 \
      -pedantic                \
      -Wall                    \
      -Wextra                  \
      -Wcast-align             \
      -Wshadow                 \
      -Wno-unused-parameter    \
      -O3                      \
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
  else
    if test "$cc" = 'clang'; then
      break
    fi
  fi

  "$cc" -g -o ./goo-test     \
    -lgmp -lcrypto           \
    -std=c89                 \
    -pedantic                \
    -Wall                    \
    -Wextra                  \
    -Wcast-align             \
    -Wshadow                 \
    -O3                      \
    -DGOO_HAS_GMP            \
    -DGOO_HAS_CRYPTO         \
    ./src/goo/drbg.c         \
    ./src/goo/hmac.c         \
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
done
