# microsoft-webhub-ffi

C-compatible FFI boundary for the [webhub](https://github.com/microsoft/webhub) framework. Exposes the webhub renderer to any host language via a stable C ABI.

## Overview

`microsoft-webhub-ffi` compiles to a `cdylib` (`libwebhub_ffi.so` / `webhub_ffi.dll` / `libwebhub_ffi.dylib`) that host language bindings (e.g. .NET, Node.js) load at runtime. The generated C header (`webhub_ffi.h`) describes the full public API.

Production hosts should call `webhub_protocol_create` once when loading
`protocol.bin`, then pass that handle to the render, partial,
component-template, and token functions. This avoids protobuf decoding and
deterministic index construction on every request. Release the shared handle with
`webhub_protocol_destroy`.

## Documentation

See the [webhub repository](https://github.com/microsoft/webhub) for full usage guides and integration examples.

## License

MIT - Copyright (c) Microsoft Corporation.
