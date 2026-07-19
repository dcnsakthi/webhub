// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, attr } from "@microsoft/webhub-framework";

export class webhubBlockquote extends webhubElement {
  @attr appearance: string = "info";
  @attr title: string = "";
  @attr icon: string = "ℹ️";
}

webhubBlockquote.define("webhub-blockquote");
