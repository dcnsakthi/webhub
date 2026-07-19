# webhub Electron Integration

Wraps any pre-built webhub app in a frameless Electron desktop window using the `@microsoft/webhub` package.

## Prerequisites

1. Build the native addon:

```bash
cargo build -p microsoft-webhub-node --release
```

2. Build the `@microsoft/webhub` package:

```bash
pnpm --filter @microsoft/webhub build
```

3. Install workspace dependencies:

```bash
pnpm install
```

4. Build a webhub app (e.g. contact-book-manager):

```bash
cargo run -p microsoft-webhub-cli -- build ../../app/contact-book-manager/src --out ../../app/contact-book-manager/dist --css link --plugin=webhub
esbuild ../../app/contact-book-manager/src/index.ts --bundle --outfile=../../app/contact-book-manager/dist/index.js --format=esm
```

## Usage

```bash
# contact-book-manager (webhub Framework)
pnpm start ../../app/contact-book-manager/dist ../../app/contact-book-manager/data/state.json --plugin=webhub
```

## CLI Arguments

| Argument | Description |
|---|---|
| `dist-dir` | **(required)** Path to the app's `dist/` directory containing `protocol.bin` and CSS/JS assets |
| `state.json` | **(required)** Path to the state JSON file |
| `--plugin=<name>` | Hydration plugin identifier (see the webhub documentation for available plugins) _(optional)_ |
