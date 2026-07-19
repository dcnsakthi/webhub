// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement } from '@microsoft/webhub-framework';

export class SectionPage extends webhubElement {
  counterLabel!: HTMLSpanElement;
  onCounterClick(): void {
    this.counterLabel.textContent = String(Number(this.counterLabel.textContent) + 1);
  }
}
SectionPage.define('section-page');
