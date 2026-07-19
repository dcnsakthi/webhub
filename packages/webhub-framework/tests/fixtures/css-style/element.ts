// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement } from '../../../src/index.js';

export class TestStyleHost extends webhubElement {
  spawnChild(): void {
    const slot = (this.shadowRoot ?? this).querySelector('.slot');
    if (!(slot instanceof HTMLDivElement)) {
      throw new Error('Missing .slot container');
    }
    if (!slot.querySelector('test-style-child')) {
      slot.appendChild(document.createElement('test-style-child'));
    }
  }
}

export class TestStyleChild extends webhubElement {}

TestStyleHost.define('test-style-host');
TestStyleChild.define('test-style-child');
