// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PLATFORMS: Record<string, string> = {
  "darwin-arm64": "@microsoft/webhub-darwin-arm64",
  "darwin-x64": "@microsoft/webhub-darwin-x64",
  "linux-x64": "@microsoft/webhub-linux-x64",
  "linux-arm64": "@microsoft/webhub-linux-arm64",
  "win32-x64": "@microsoft/webhub-win32-x64",
  "win32-arm64": "@microsoft/webhub-win32-arm64",
};

const ADDON_NAMES: Record<string, string> = {
  darwin: "libwebhub_node.dylib",
  linux: "libwebhub_node.so",
  win32: "webhub_node.dll",
};

export function platformKey(): string {
  return `${process.platform}-${os.arch()}`;
}

export function packageName(): string {
  const key = platformKey();
  const name = PLATFORMS[key];
  if (!name) {
    throw new Error(
      `[webhub] Unsupported platform: ${key}. ` +
        `Supported: ${Object.keys(PLATFORMS).join(", ")}`,
    );
  }
  return name;
}

/**
 * Resolve a file from the platform-specific package, with fallback to
 * local cargo build output for workspace development.
 *
 * @param kind — "bin" for CLI binary, "addon" for .node file
 * @returns Absolute path, or null if not found.
 */
export function resolve(kind: "bin" | "addon"): string | null {
  // Environment variable overrides
  if (kind === "bin" && process.env["webhub_BINARY_PATH"]) {
    return process.env["webhub_BINARY_PATH"];
  }
  if (kind === "addon" && process.env["webhub_ADDON_PATH"]) {
    return process.env["webhub_ADDON_PATH"];
  }

  // Try platform-specific npm package
  try {
    const pkg = packageName();
    const pkgDir = path.dirname(require.resolve(`${pkg}/package.json`));
    if (kind === "bin") {
      const binName = process.platform === "win32" ? "webhub.exe" : "webhub";
      const binPath = path.join(pkgDir, "bin", binName);
      if (existsSync(binPath)) return binPath;
    } else {
      const addonPath = path.join(pkgDir, "webhub.node");
      if (existsSync(addonPath)) return addonPath;
    }
  } catch {
    // Fall through to workspace fallback
  }

  // Workspace fallback: look for cargo build output.
  // __dirname is packages/webhub/dist (compiled) or packages/webhub/src (source)
  // so ../../.. reaches the workspace root.
  const workspaceRoot = path.resolve(__dirname, "..", "..", "..");
  const releasePath = path.join(workspaceRoot, "target", "release");

  if (kind === "bin") {
    const binName = process.platform === "win32" ? "webhub.exe" : "webhub";
    const binPath = path.join(releasePath, binName);
    if (existsSync(binPath)) return binPath;
    // Also check debug
    const debugPath = path.join(workspaceRoot, "target", "debug", binName);
    if (existsSync(debugPath)) return debugPath;
  } else {
    const addonName = ADDON_NAMES[process.platform] ?? "libwebhub_node.so";
    const addonPath = path.join(releasePath, addonName);
    if (existsSync(addonPath)) return addonPath;
    const debugPath = path.join(workspaceRoot, "target", "debug", addonName);
    if (existsSync(debugPath)) return debugPath;
  }

  return null;
}
