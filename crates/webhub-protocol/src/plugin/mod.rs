// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Plugin-specific protocol helpers for framework hydration metadata.

mod fast;
mod webhub;

pub use fast::FastElementData;
pub use webhub::webhubElementData;
