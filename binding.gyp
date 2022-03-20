{
    "targets": [
        {
            "target_name": "calculate",
            "sources": ["calculate.cc"],
            'include_dirs': [
                "<!(node -p \"require('node-addon-api').include_dir\")",
                "."
            ],
            'libraries': [],
            'dependencies': [
                "<!(node -p \"require('node-addon-api').gyp\")"
            ],
            'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ],
            'cflags!': [ '-fno-exceptions' ],
            'cflags_cc!': [ '-fno-exceptions' ],
            'conditions': [
                ["OS=='win'", {
                "defines": [
                    "_HAS_EXCEPTIONS=1"
                ],
                "msvs_settings": {
                    "VCCLCompilerTool": {
                    "ExceptionHandling": 1
                    },
                },
                }],
                ["OS=='mac'", {
                'xcode_settings': {
                    'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
                    'CLANG_CXX_LIBRARY': 'libc++',
                    'MACOSX_DEPLOYMENT_TARGET': '10.7',
                },
                }],
            ],
             'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ]
        }
    ]
}