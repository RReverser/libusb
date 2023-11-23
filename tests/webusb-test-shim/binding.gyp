{
  'targets': [
    {
      'target_name': "umockdev-server-bindings",
      'sources': [ "umockdev-server-bindings.cpp", "../umockdev-server.c" ],
      'include_dirs': [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<!@(pkg-config umockdev-1.0 --cflags-only-I | sed s/-I//g)",
        "../../libusb"
      ],
      'dependencies': [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      'libraries': [
        "<!(pkg-config umockdev-1.0 --libs)"
      ],
      'defines': [
        'NAPI_DISABLE_CPP_EXCEPTIONS',
        'NAPI_VERSION=6',
      ],
    }
  ]
}
