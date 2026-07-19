// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, attr } from '../../../src/index.js';

export class TestRef extends webhubElement {
  @attr value = 'hello';
  inputEl!: HTMLInputElement;

  readInput(): void {
    this.value = this.inputEl.value;
  }

  focusInput(): void {
    this.inputEl.focus();
  }
}

TestRef.define('test-ref');

