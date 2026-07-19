// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '@microsoft/webhub-framework';

// Has local state (clickCount) that should survive keep-alive reactivation.
export class PageKeepAlive extends webhubElement {
  @observable clickCount = 0;

  onIncrement = (): void => {
    this.clickCount++;
  };
}
