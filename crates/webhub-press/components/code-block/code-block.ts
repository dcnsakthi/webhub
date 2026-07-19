// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from "@microsoft/webhub-framework";

export class CodeBlock extends webhubElement {
  @observable label = "Copy";

  copy(): void {
    const code = this.querySelector("code");
    if (code) {
      navigator.clipboard.writeText(code.textContent || "").then(() => {
        this.label = "Copied!";
        setTimeout(() => {
          this.label = "Copy";
        }, 1500);
      });
    }
  }
}

CodeBlock.define("code-block");
