// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, attr } from '@microsoft/webhub-framework';

export class CbHeader extends webhubElement {
  @attr searchQuery = '';

  onInput(e: Event): void {
    const input = e.currentTarget;
    if (!(input instanceof HTMLInputElement)) return;

    this.searchQuery = input.value;
    this.$emit('search-change', { value: input.value });
  }
}

CbHeader.define('cb-header');
