// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, attr } from '@microsoft/webhub-framework';

export class MpCategoryNav extends webhubElement {
  @attr({ attribute: 'all-active', mode: 'boolean' }) allActive = false;
  @attr({ attribute: 'current-label' }) currentCategoryLabel = 'All';
  mobileDropdown!: HTMLDetailsElement;

  closeMobileDropdown(): void {
    if (this.mobileDropdown) {
      this.mobileDropdown.open = false;
    }
  }
}

MpCategoryNav.define('mp-category-nav');
