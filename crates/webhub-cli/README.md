# microsoft-webhub-cli

Command-line tool for the [webhub](https://github.com/microsoft/webhub) framework — build, serve, and inspect webhub applications.

## Install

```bash
cargo install microsoft-webhub-cli
```

This installs the `webhub` binary.

## Commands

### `webhub build`

Build a webhub application into a compiled protocol and CSS files.

```bash
webhub build [APP] --out <DIR> [--entry <FILE>] [--css <MODE>] [--plugin <NAME>] [--asset-file-name-template <TEMPLATE>] [--css-public-base <BASE>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `APP` | `.` | Template/component directory |
| `--out` | *(required)* | Output directory for protocol.bin + CSS, or a `.bin` file path to customize the protocol filename (e.g. `./dist/app1.bin`) |
| `--entry` | `index.html` | Entry HTML file |
| `--css` | `link` | CSS mode: `link` (external files) or `style` (inline) |
| `--plugin` | *(none)* | Plugin identifier (see [Plugins](https://dcnsakthi.github.io/webhub/guide/concepts/plugins/) for available identifiers) |
| `--asset-file-name-template` | `[name].[ext]` | Emitted asset filename template. Tokens: `[name]`, `[hash]`, `[ext]` |
| `--css-public-base` | *(none)* | Optional base URL/path prepended to Link-mode stylesheet hrefs |

```bash
webhub build ./src --out ./dist
webhub build ./src --out ./dist --plugin webhub --css style
webhub build ./src --out ./dist/app1.bin
webhub build ./src --out ./dist --asset-file-name-template "[name]-[hash].[ext]"
webhub build ./src --out ./dist --asset-file-name-template "[name]-[hash].[ext]" --css-public-base "https://cdn.example.com/assets"
```

### `webhub serve`

Start a development server with live rebuild and HMR.

```bash
webhub serve [APP] [--state <FILE>] [--servedir <DIR>] [--port <PORT>] [--api-port <PORT>] [--plugin <NAME>] [--watch] [--asset-file-name-template <TEMPLATE>] [--css-public-base <BASE>]
```

| Option | Default | Description |
|--------|---------|-------------|
| `APP` | `.` | Template/component directory |
| `--state` | *(none)* | JSON state file for rendering |
| `--servedir` | *(none)* | Static assets directory served at `/*` |
| `--port` | `3000` | Server port |
| `--api-port` | *(none)* | Proxy API requests to this port |
| `--plugin` | *(none)* | Plugin identifier (see [Plugins](https://dcnsakthi.github.io/webhub/guide/concepts/plugins/) for available identifiers) |
| `--watch` | off | Enable file watching + HMR |
| `--asset-file-name-template` | `[name].[ext]` | Emitted asset filename template. Tokens: `[name]`, `[hash]`, `[ext]` |
| `--css-public-base` | *(none)* | Optional base URL/path prepended to Link-mode stylesheet hrefs |

```bash
webhub serve ./src --state ./data/state.json --port 3000 --watch
webhub serve ./src --plugin webhub --servedir ./dist --port 3004 --api-port 3014 --watch
```

Features:
- Renders HTML at `/` and all route paths
- Serves static files from `--servedir`
- JSON partials for client-side navigation (`Accept: application/json`)
- HMR polling at `/hmr` when `--watch` is enabled
- API proxy when `--api-port` is set

### `webhub inspect`

Convert a compiled protocol to JSON for debugging.

```bash
webhub inspect <FILE>
```

```bash
webhub inspect ./dist/protocol.bin
```

## App Layout

```
my-app/
├── src/
│   ├── index.html          # entry template
│   ├── my-card.html         # component template
│   └── my-card.css          # component styles
├── data/
│   └── state.json           # render state
└── dist/                    # build output
    ├── protocol.bin
    └── my-card.css
```

## License

MIT
