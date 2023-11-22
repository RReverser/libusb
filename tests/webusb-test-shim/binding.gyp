{
  'targets': [
    {
      'target_name': "umockdev-server-bindings",
      'sources': [ "umockdev-server-bindings.cpp" ],
      'ldflags': ["../umockdev-server.so"],
      'include_dirs': ["<!@(node -p \"require('node-addon-api').include\")"],
      'dependencies': ["<!(node -p \"require('node-addon-api').gyp\")"],
      'defines': [
        'NAPI_DISABLE_CPP_EXCEPTIONS',
        'NAPI_VERSION=6',
      ],
    }
  ]
}
