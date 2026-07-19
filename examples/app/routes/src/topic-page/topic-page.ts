// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement } from '@microsoft/webhub-framework';

export class TopicPage extends webhubElement {
  counterLabel!: HTMLSpanElement;
  onCounterClick(): void {
    this.counterLabel.textContent = String(Number(this.counterLabel.textContent) + 1);
  }
}
TopicPage.define('topic-page');
