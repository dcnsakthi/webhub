# microsoft-webhub-tokens

Shared CSS token helpers for RUST servers to use with CSS token hoisting.

## Overview

Design token loading, filtering, and CSS generation for the webhub framework.
Token resolution emits declarations for parser token candidates present in each
theme, following present transitive `var(--token)` dependencies while trusting
theme internals.

## Documentation

See the [webhub repository](https://github.com/microsoft/webhub) for full usage guides and examples.

## License

MIT — Copyright (c) Microsoft Corporation.