// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement } from '@microsoft/webhub-framework';

export class MpFilterList extends webhubElement {
  mobileDropdown!: HTMLDetailsElement;

  closeMobileDropdown(): void {
    this.mobileDropdown.open = false;
  }
}

MpFilterList.define('mp-filter-list');
