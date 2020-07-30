{
  "variables": {
    "conditions": [
      ["OS != 'win'", {
        "with_gmp%": "<!(./utils/has_gmp.sh)"
      }, {
        "with_gmp%": "false"
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
      "conditions": [
        ["OS != 'mac' and OS != 'win'", {
          "cflags": [
            "-std=c89",
            "-pedantic",
            "-Wcast-align",
            "-Wno-long-long",
            "-Wshadow"
          ]
        }],
        ["OS == 'mac'", {
          "xcode_settings": {
            "GCC_C_LANGUAGE_STANDARD": "c89",
            "WARNING_CFLAGS": [
              "-pedantic",
              "-Wcast-align",
              "-Wno-long-long",
              "-Wshadow"
            ]
          }
        }],
        ["OS == 'win'", {
          "msvs_disabled_warnings=": [
            4146, # negation of unsigned integer
            4244, # implicit integer demotion
            4267, # implicit size_t demotion
            4334  # implicit 32->64 bit shift
          ]
        }],
        ["node_byteorder == 'big'", {
          "defines": [
            "WORDS_BIGENDIAN"
          ]
        }],
        ["with_gmp == 'true'", {
          "defines": [
            "GOO_HAS_GMP"
          ],
          "direct_dependent_settings": {
            "libraries": [
              "-lgmp"
            ]
          }
        }, {
          "sources": [
            "./src/goo/mini-gmp.c"
          ],
          "conditions": [
            ["OS != 'mac' and OS != 'win'", {
              "cflags": [
                "-Wno-unused-parameter",
                "-Wno-unused-variable",
                "-Wno-sign-compare"
              ]
            }],
            ["OS == 'mac'", {
              "xcode_settings": {
                "WARNING_CFLAGS": [
                  "-Wno-unused-parameter",
                  "-Wno-unused-variable",
                  "-Wno-sign-compare"
                ]
              }
            }]
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
      "conditions": [
        ["OS != 'mac' and OS != 'win'", {
          "cflags": [
            "-std=c99"
          ]
        }],
        ["OS == 'mac'", {
          "xcode_settings": {
            "GCC_C_LANGUAGE_STANDARD": "c99"
          }
        }]
      ]
    }
  ]
}
