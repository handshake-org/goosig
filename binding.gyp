{
  "targets": [{
    "target_name": "goosig",
    "sources": [
      "./src/goo/drbg.c",
      "./src/goo/goo.c",
      "./src/goo/hmac.c",
      "./src/goo/sha256.c",
      "./src/goosig.cc",
      "./src/random.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wextra",
      "-Wno-unknown-warning",
      "-O3"
    ],
    "cflags_c": [
      "-std=c89",
      "-pedantic",
      "-Wcast-align",
      "-Wshadow",
      "-Wno-long-long"
    ],
    "cflags_cc+": [
      "-std=c++0x",
      "-Wno-cast-function-type"
    ],
    "include_dirs": [
      "<!(node -e \"require('nan')\")"
    ],
    "defines": [
      "GOO_HAS_OPENSSL"
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
        "cflags_c": [
          "-Wno-unused-parameter"
        ],
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
