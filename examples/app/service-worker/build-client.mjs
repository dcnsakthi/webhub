// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { runwebhubClientBuild } from "../../build-client.mjs";

await runwebhubClientBuild({
  entryPoints: ["src/app.ts", "src/service-worker.ts"],
  outdir: "public",
  target: "es2022",
  external: ["./wasm/handler/webhub_wasm_handler.js"],
});
