{
  "targets": [{
    "target_name": "goosig",
    "sources": [
      "./src/goo/drbg.c",
      "./src/goo/goo.c",
      "./src/goo/hmac.c",
      "./src/goo/sha256.c",
      "./src/goosig.cc"
    ],
    "cflags": [
      "-Wall",
      "-Wextra",
      "-O3"
    ],
    "cflags_c": [
      "-std=c89",
      "-pedantic",
      "-Wcast-align",
      "-Wshadow",
      "-Wno-long-long"
    ],
    "variables": {
      "conditions": [
        ["OS=='win'", {
          "with_gmp%": "false"
        }, {
          "with_gmp%": "<!(./utils/has_gmp.sh)"
        }]
      ]
    },
    "conditions": [
      ["node_byteorder=='big'", {
        "defines": [
          "WORDS_BIGENDIAN"
        ]
      }],
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
        ],
        "cflags_c": [
          "-Wno-unused-parameter",
          "-Wno-sign-compare"
        ]
      }]
    ]
  }]
}
