// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, attr } from '@microsoft/webhub-framework';

export class CbSearchBar extends webhubElement {
  @attr placeholder = 'Search contacts...';
  @attr value = '';

  onInput(e: Event): void {
    const input = e.currentTarget;
    if (!(input instanceof HTMLInputElement)) return;

    this.value = input.value;
    this.$emit('search-change', { value: this.value });
  }

  onClear(): void {
    this.value = '';
    this.$emit('search-change', { value: '' });
  }
}

CbSearchBar.define('cb-search-bar');
