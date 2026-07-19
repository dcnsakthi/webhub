# Examples

This directory contains runnable webhub examples.

## Structure

- `app/` — source app examples (templates, assets, data)
- `integration/` — host-language integrations that load `protocol.bin` and render HTML

Current entries:

| Example | Description |
|---------|-------------|
| `app/hello-world` | Basic webhub app with signals, for-loops, if-conditions |
| `app/calculator` | webhub Framework calculator with custom views and events |
| `app/todo-fast` | @microsoft/fast-element 3.x hydration app with components, `@event` bindings, `f-ref`, and `<f-template>` injection |
| `app/todo-webhub` | webhub Framework hydration app — components, `@click`, `w-ref`, compiled templates |
| `app/contact-book-manager` | Full CRUD contact manager with webhub Framework + router + Node API |
| `app/component-assets` | No-router webhub Framework app that lazy-loads a static component asset on demand |
| `app/commerce` | webhub Framework hydration app with a Rust backend for commerce demo app, dozens of controls |
| `app/routes` | Nested declarative routing demo showing 4-level deep routes, full server side and client handoff |
| `app/service-worker` | Static/CDN service worker app using `webhub_wasm_handler` to stream WASM-rendered chunks from public API state |
| `integration/node` | Node.js integration via native addon |
| `integration/rust` | Rust integration via `webhub-handler` |

## Quick Start

Run any app with the `dev` xtask. It builds + serves the app and watches for changes:

```bash
# From the repository root:
pnpm install

# Run any app — replace <name> with a directory under examples/app/
cargo xtask dev <name>

# Examples
cargo xtask dev hello-world
cargo xtask dev calculator
cargo xtask dev contact-book-manager
cargo xtask dev component-assets
cargo xtask dev todo-webhub
```

Each app's `package.json` also exposes `pnpm start`, which delegates to the same xtask.

## More Details

See integration-specific READMEs:

- [integration/node/README.md](integration/node/README.md)
- [integration/rust/README.md](integration/rust/README.md)
- [app/service-worker/README.md](app/service-worker/README.md)
