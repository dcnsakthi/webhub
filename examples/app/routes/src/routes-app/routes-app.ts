// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement } from '@microsoft/webhub-framework';

export class RoutesApp extends webhubElement {
  counterLabel!: HTMLSpanElement;
  onCounterClick(): void {
    this.counterLabel.textContent = String(Number(this.counterLabel.textContent) + 1);
  }
}
RoutesApp.define('routes-app');
