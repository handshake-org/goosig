{
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
      "-Wextra",
      "-Wno-unknown-warning",
      "-Wno-unused-function",
      "-O3"
    ],
    "cflags_c": [
      "-std=c89",
      "-pedantic",
      "-Wcast-align",
      "-Wshadow",
      "-Wno-long-long",
      "-Wno-overlength-strings"
    ],
    "cflags_cc+": [
      "-std=c++0x",
      "-Wno-cast-function-type"
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
          "with_gmp%": "<!(./utils/has_gmp.sh)"
        }]
      ]
    },
    "conditions": [
      ["with_gmp=='true'", {
        "defines": [
          "GOO_HAS_GMP"
        ],
        "libraries": [
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
      }],
      ["OS=='mac'", {
        "include_dirs": [
          "/usr/local/include"
        ],
        "libraries": [
          "-L/usr/local/lib"
        ],
        "xcode_settings": {
          "MACOSX_DEPLOYMENT_TARGET": "10.7",
          "OTHER_CPLUSPLUSFLAGS": [
            "-stdlib=libc++"
          ]
        }
      }]
    ]
  }]
}
