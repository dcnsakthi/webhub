---
description: "Rebrands this webui monorepo to webhub across Rust, npm, and .NET, then creates and pushes a new GitHub repository"
argument-hint: "[repoOwner=...] [repoName=webhub] [visibility={public|private}]"
---

# Rebrand WebUI to WebHub

Rename every `webui`/`WebUI` identifier in this monorepo to the equivalent `webhub`/`WebHub` form, validate the result builds cleanly, then create a new GitHub repository and push the rebranded codebase to it.

## Inputs

* ${input:repoOwner}: (Required) GitHub owner or organization that will own the new repository.
* ${input:repoName:webhub}: (Optional, defaults to `webhub`) Name of the new GitHub repository.
* ${input:visibility:public}: (Optional, defaults to `public`) Repository visibility, either `public` or `private`.

## Rebrand Log

Create and update a `.copilot-tracking/sandbox/{{YYYY-MM-DD}}-webui-to-webhub-001/rebrand-log.md` file, progressively documenting:

* Every folder, file, and identifier renamed, grouped by ecosystem (Rust, npm, .NET, docs, CI).
* Case-variant mappings applied (`webui`→`webhub`, `WebUI`→`WebHub`, `WEBUI`→`WEBHUB`, `Webui`→`Webhub`, `web-ui`→`web-hub`).
* Build and test validation results after each ecosystem's rename.
* Any reference intentionally left unchanged (for example, third-party license text or external URLs) and why.
* The final GitHub repository URL and push result.

## Required Steps

### Step 1: Inventory References

1. Search the workspace for all case variants of `webui` across file names, folder names, and file contents: `webui`, `WebUI`, `WEBUI`, `Webui`, `web-ui`.
2. Group findings by ecosystem: Rust (`Cargo.toml` package names, crate folder names under `crates/`, workspace dependency entries), npm (`package.json` name fields under `packages/`, cross-package `dependencies`/`devDependencies`, `pnpm-workspace.yaml`), .NET (`dotnet/Microsoft.WebUI.sln`, `Directory.Build.props`/`.targets`, namespaces, assembly names, `Microsoft.WebUI.Runtime.*` project folders), docs (`DESIGN.md`, `README.md`, `docs/`), CI (`azure-pipelines-cd.yml`), and misc (`webui.code-workspace`, `.github/copilot-instructions.md`).
3. Record the inventory in the Rebrand Log before making changes.

### Step 2: Rename Folders and Files

1. Rename crate folders under `crates/` from `webui*` to `webhub*`.
2. Rename npm package folders under `packages/` from `webui*` to `webhub*`.
3. Rename `.NET` project folders and the solution file from `Microsoft.WebUI.*` to `Microsoft.WebHub.*`, including `dotnet/Microsoft.WebUI.sln` and each `dotnet/runtime/Microsoft.WebUI.Runtime.*` folder.
4. Rename `webui.code-workspace` to `webhub.code-workspace`.
5. Update the Rebrand Log with every path renamed.

### Step 3: Replace Identifiers in File Contents

1. Update `Cargo.toml` `[package] name` fields and every `[workspace.dependencies]` entry and per-crate dependency reference to match renamed crate names.
2. Update each `package.json` `name` field and cross-package dependency references, then refresh `pnpm-lock.yaml` accordingly.
3. Update .NET namespaces, assembly names, `<ProjectReference>` paths, and `Microsoft.WebUI.sln` project entries to the `WebHub` equivalents.
4. Update prose and configuration references in `DESIGN.md`, `README.md`, `docs/`, `azure-pipelines-cd.yml`, and `.github/copilot-instructions.md`, preserving the original casing pattern for each match (`webui`→`webhub`, `WebUI`→`WebHub`, `WEBUI`→`WEBHUB`, `Webui`→`Webhub`, `web-ui`→`web-hub`).
5. Leave third-party license text, external URLs, and unrelated matches unchanged; note any skipped match in the Rebrand Log with a reason.

### Step 4: Validate the Rebrand

1. Run `cargo xtask check` and resolve any failures introduced by the rename.
2. Run the npm/pnpm install and build for `packages/` and `docs/`, resolving any failures.
3. Run a `dotnet build` against `dotnet/Microsoft.WebHub.sln`, resolving any failures.
4. Record each validation result in the Rebrand Log before proceeding.

### Step 5: Create and Push the New Repository

1. Confirm the target GitHub owner, repository name, and visibility with the user before creating anything, since this step is not easily reversible.
2. Create the new GitHub repository using the provided repoOwner, repoName, and visibility inputs.
3. Push the rebranded codebase, including all branches and tags needed for a working clone, to the new repository.
4. Record the final repository URL and push confirmation in the Rebrand Log.

## Required Protocol

1. Complete Step 1 before making any destructive change so the Rebrand Log reflects the full scope up front.
2. Confirm with the user before Step 5, since creating and pushing to a new repository is a hard-to-reverse, shared-system action.
3. Follow Steps 2 through 4 per ecosystem, validating after each ecosystem rather than deferring all validation to the end.
4. If validation in Step 4 fails, return to Step 3 for the affected ecosystem before continuing.
5. Finalize the Rebrand Log with a summary of all renames and the push result once Step 5 completes.
