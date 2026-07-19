# microsoft-webhub-dev-server

Shared dev-server primitives for webhub tooling.

This crate provides three pieces that any webhub dev server can compose:

- **`LiveReload`** — Server-Sent Events broadcaster. Cheap to clone, ships
  its own actix handler, generates the matching browser-side `<script>`,
  and injects it before `</body>`.
- **`watch::spawn_watcher`** — Debounced filesystem watcher backed by
  `notify`. Calls a closure once per debounce window.
- **`path::*`** — URL path utilities for serving files under a `basePath`
  prefix without traversal vulnerabilities.

Used by `microsoft-webhub-press` (static-site preview) and the `webhub serve`
CLI command (HMR for app development).

This crate is not intended for direct end-user consumption; its public API
follows the webhub workspace versioning rather than semver.

## Documentation

See the [webhub repository](https://github.com/microsoft/webhub) for full usage guides and examples.

## License

MIT — Copyright (c) Microsoft Corporation.