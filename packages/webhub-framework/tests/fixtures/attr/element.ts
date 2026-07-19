// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, attr, observable } from '../../../src/index.js';

export class TestAttr extends webhubElement {
  @attr label = 'Status';
  @attr({ attribute: 'display-value' }) displayValue = 'Ready';
  @attr({ attribute: 'cta-href' }) ctaHref = '/checkout';
  @attr({ mode: 'boolean', attribute: 'is-active' }) isActive = false;
  @observable itemId = '42';
  @observable tag = 'demo';

  noop(): void {}
}

TestAttr.define('test-attr');

