{
  "variables": {
    "conditions": [
      ["OS == 'win'", {
        "with_gmp%": "false"
      }, {
        "with_gmp%": "<!(./utils/has_gmp.sh)"
      }]
    ]
  },
  "targets": [
    {
      "target_name": "goo",
      "type": "static_library",
      "sources": [
        "./src/goo/drbg.c",
        "./src/goo/goo.c",
        "./src/goo/hmac.c",
        "./src/goo/sha256.c"
      ],
      "cflags": [
        "-std=c89",
        "-pedantic",
        "-Wcast-align",
        "-Wno-long-long",
        "-Wshadow"
      ],
      "conditions": [
        ["node_byteorder == 'big'", {
          "defines": [
            "WORDS_BIGENDIAN"
          ]
        }],
        ["with_gmp == 'true'", {
          "defines": [
            "GOO_HAS_GMP"
          ]
        }, {
          "sources": [
            "./src/goo/mini-gmp.c"
          ],
          "cflags": [
            "-Wno-unused-parameter",
            "-Wno-unused-variable",
            "-Wno-sign-compare"
          ]
        }]
      ]
    },
    {
      "target_name": "goosig",
      "dependencies": [
        "goo"
      ],
      "sources": [
        "./src/goosig.c"
      ],
      "cflags": [
        "-std=c99"
      ],
      "conditions": [
        ["with_gmp == 'true'", {
          "libraries": [
            "-lgmp"
          ]
        }]
      ]
    }
  ]
}
