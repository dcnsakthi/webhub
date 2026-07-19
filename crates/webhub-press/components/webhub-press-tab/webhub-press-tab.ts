// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement } from "@microsoft/webhub-framework";

export class webhubPressTab extends webhubElement {
  select(): void {
    this.$emit("tab-select", { tab: this });
  }
}

webhubPressTab.define("webhub-press-tab");
