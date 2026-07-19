
### todo-webhub (webhub Framework hydration)

```bash
# Install JS dependencies
pnpm install

# Build client JavaScript + projection manifest, then protocol.bin
pnpm build

# Or use the dev server with live rendering
cd examples/app/todo-webhub
node ../../build-client.mjs --watch
cargo run -p microsoft-webhub-cli -- serve ./src --state ./data/state.json --plugin=webhub --projection-manifest ./dist/webhub-projection.json --servedir ./dist --port 3006 --watch
```

### Using `--plugin=webhub`

The `--plugin=webhub` flag enables:

1. **Parser plugin (`webhubParserPlugin`)** — During `webhub build`:
   - Skips webhub Framework runtime attributes (`@click`, `w-ref`, etc.)
   - Counts dynamic attribute bindings per element and emits `Plugin` protocol fragments
   - Tracks components and generates `<w-template name="...">` client template strings

2. **Handler plugin (`webhubHydrationPlugin`)** — During rendering:
   - Wraps signals, for-loops, and if-conditions in `<!--w-b:start:INDEX:NAME-->` comment markers
   - Wraps for-loop items in `<!--w-r:start:INDEX-->` comment markers
   - Emits `data-w-b-*` / `data-w-c-*` attributes for element bindings
   - Manages per-component/per-item scope counters for binding indices

These markers enable `@microsoft/webhub-framework`'s client-side hydration.