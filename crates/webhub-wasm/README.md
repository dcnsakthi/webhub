# microsoft-webhub-wasm

WebAssembly bindings for the [webhub](https://github.com/microsoft/webhub) framework, built with `wasm-bindgen`.

## Overview

`microsoft-webhub-wasm` can be built as three browser bundles:

| Feature | Bundle | Exports |
|---------|--------|---------|
| `handler` | `webhub_wasm_handler.js` | `Protocol` |
| `parser` | `webhub_wasm_parser.js` | `build_protocol` |
| `all` | `webhub_wasm_all.js` | Parser and handler exports |

The default feature is `all`, which powers the online playground. Consumers that only need to render prebuilt protobuf protocol bytes should use the handler bundle to avoid shipping parser code.

Construct `Protocol` once from protocol bytes. It exposes `render`,
`renderStream`, `renderPartial`, `renderComponentTemplates`, and `tokens`.
Streaming callbacks are coalesced around a 16 KiB target before crossing into
JavaScript.

## Building

```bash
cargo xtask build-wasm
```

This writes the three generated bundles under `docs/.webhub-press/public/wasm/`.

## Documentation

See the [webhub repository](https://github.com/microsoft/webhub) for full usage guides and examples.

## License

MIT - Copyright (c) Microsoft Corporation.
