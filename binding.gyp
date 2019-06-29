{
  "variables": {
    "goo_byteorder%":
      "<!(python -c \"from __future__ import print_function; import sys; print(sys.byteorder)\")"
  },
  "targets": [{
    "target_name": "goosig",
    "sources": [
      "./src/goo/drbg.c",
      "./src/goo/goo.c",
      "./src/goo/hmac.c",
      "./src/goo/random.c",
      "./src/goosig.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wno-implicit-fallthrough",
      "-Wno-uninitialized",
      "-Wno-unused-function",
      "-Wextra",
      "-O3"
    ],
    "cflags_c": [
      "-std=c99",
      "-Wno-unused-parameter"
    ],
    "cflags_cc+": [
      "-std=c++0x",
      "-Wno-maybe-uninitialized",
      "-Wno-cast-function-type",
      "-Wno-unused-parameter",
      "-Wno-unknown-warning-option"
    ],
    "include_dirs": [
      "<!(node -e \"require('nan')\")"
    ],
    "defines": [
      "GOO_TEST"
    ],
    "variables": {
      "conditions": [
        ["OS=='win'", {
          "conditions": [
            ["target_arch=='ia32'", {
              "openssl_root%": "C:/OpenSSL-Win32"
            }, {
              "openssl_root%": "C:/OpenSSL-Win64"
            }]
          ]
        }],
        ["OS=='win'", {
          "with_gmp%": "false"
        }, {
          "with_gmp%": "<!(utils/has_lib.sh gmpxx gmp)"
        }]
      ]
    },
    "conditions": [
      ["goo_byteorder=='little'", {
        "defines": [
          "GOO_LITTLE_ENDIAN"
        ]
      }, {
        "defines": [
          "GOO_BIG_ENDIAN"
        ]
      }],
      ["with_gmp=='true'", {
        "defines": [
          "GOO_HAS_GMP"
        ],
        "libraries": [
          "-lgmpxx",
          "-lgmp"
        ]
      }, {
        "sources": [
          "./src/goo/mini-gmp.c"
        ]
      }],
      ["OS=='win'", {
        "libraries": [
          "-l<(openssl_root)/lib/libeay32.lib"
        ],
        "include_dirs": [
          "<(openssl_root)/include"
        ]
      }, {
        "include_dirs": [
          "<(node_root_dir)/deps/openssl/openssl/include"
        ]
      }]
    ]
  }]
}
