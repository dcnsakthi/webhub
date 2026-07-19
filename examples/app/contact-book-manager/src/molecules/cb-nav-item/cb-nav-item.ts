// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, attr } from '@microsoft/webhub-framework';

export class CbNavItem extends webhubElement {
  @attr icon = '';
  @attr label = '';
  @attr count = '';
  @attr active = '';

  onClick(): void {
    this.$emit('nav-select', { label: this.label });
  }
}

CbNavItem.define('cb-nav-item');
