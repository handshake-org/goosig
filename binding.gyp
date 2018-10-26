{
  "variables": {
    "bcrypto_byteorder%":
      "<!(python -c 'from __future__ import print_function; import sys; print(sys.byteorder)')",
  },
  "targets": [{
    "target_name": "goosig",
    "sources": [
      "./src/aead/aead.c",
      "./src/whirlpool.cc"
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
      "-Wno-unknown-warning-option",
      "-Wno-deprecated-declarations"
    ],
    "include_dirs": [
      "<!(node -e \"require('nan')\")"
    ],
    "variables": {
      "conditions": [
        ["OS!='win'", {
          "cc": "<!(echo $CC)"
        }],
        ["OS=='win'", {
          "conditions": [
            ["target_arch=='ia32'", {
              "openssl_root%": "C:/OpenSSL-Win32"
            }, {
              "openssl_root%": "C:/OpenSSL-Win64"
            }]
          ]
        }]
      ]
    },
    "conditions": [
      ["bcrypto_byteorder=='little'", {
        "defines": [
          "BCRYPTO_LITTLE_ENDIAN"
        ]
      }, {
        "defines": [
          "BCRYPTO_BIG_ENDIAN"
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
  }
}
