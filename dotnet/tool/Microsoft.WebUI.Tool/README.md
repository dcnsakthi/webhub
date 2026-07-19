# Microsoft.webhub.Tool

CLI tool for building and inspecting webhub templates.

## Installation

```bash
dotnet tool install -g Microsoft.webhub.Tool
```

NuGet artifacts for this tool include this README, repository metadata, Source Link, a package license URL with license acceptance required, release notes links, discoverability tags, the `© Microsoft Corporation. All rights reserved.` notice, and `.snupkg` symbols. Release workflows stage the artifacts for manual nuget.org publishing until ESRP supports automated NuGet publishing for this project. Before publishing, staged packages and Authenticode-signable contents must be signed with a Microsoft certificate through the approved signing process.

## Usage

```bash
# Build templates into a binary protocol file
webhub build ./src --output app.webhub

# Inspect a compiled protocol file
webhub inspect app.webhub

# Start a dev server with hot reload
webhub serve ./src --state ./data/state.json --port 3001 --watch
```

## Configuration

The tool locates the native `webhub` binary using:

1. `webhub_BINARY_PATH` environment variable (directory containing the binary)
2. System PATH

## License

MIT. NuGet package metadata uses © Microsoft Corporation. All rights reserved.
