# microsoft-webhub-protocol

Protobuf protocol definitions and serialization for the [webhub](https://github.com/microsoft/webhub) framework. Defines the binary format that carries compiled template data from the build step to the renderer.

## Overview

`microsoft-webhub-protocol` uses `prost` for zero-copy protobuf encoding and decoding. It defines the `webhubProtocol` message and all fragment types that flow between the parser and handler.

## Documentation

See the [webhub repository](https://github.com/microsoft/webhub) for full usage guides and examples.

## License

MIT — Copyright (c) Microsoft Corporation.
