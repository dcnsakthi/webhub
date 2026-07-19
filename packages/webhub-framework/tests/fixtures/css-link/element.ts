// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement } from '../../../src/index.js';

export class TestLinkHost extends webhubElement {
  spawnChild(): void {
    const root = this.shadowRoot ?? this;
    const slot = root.querySelector('.slot');
    if (!(slot instanceof HTMLDivElement)) {
      throw new Error('Missing .slot container');
    }
    if (!slot.querySelector('test-link-child')) {
      slot.appendChild(document.createElement('test-link-child'));
    }
  }
}

export class TestLinkChild extends webhubElement {}

TestLinkHost.define('test-link-host');
TestLinkChild.define('test-link-child');
