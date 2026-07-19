# webhub Node.js Integration Example

Minimal example showing how to use the `@microsoft/webhub` npm package to build
templates and render HTML with state data — all from Node.js.

## Prerequisites

1. Build the native addon:

```bash
cargo build -p microsoft-webhub-node
```

2. Build the `@microsoft/webhub` package:

```bash
pnpm --filter @microsoft/webhub build
```

3. Install workspace dependencies:

```bash
pnpm install
```

## Usage

Build the hello-world app and render it with state data:

```bash
node index.js
```

Or render a pre-built protocol with custom state:

```bash
node index.js ../../app/hello-world/dist/protocol.bin ../../app/hello-world/data/state.json
```

This uses the `@microsoft/webhub` package API (`build()` and `Protocol`) which
automatically resolves the native addon from the workspace build output.
`Protocol.render()` and `Protocol.renderStream()` reuse the decoded protocol.
