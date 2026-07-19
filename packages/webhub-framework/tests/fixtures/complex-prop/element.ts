// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '../../../src/index.js';

export class TestItemList extends webhubElement {
  @observable items: Array<{ name: string }> = [];
}

/** Child component with a conditional block driven by a complex :data property. */
export class TestCondChild extends webhubElement {
  @observable data: { showHeader?: boolean; label?: string } = {};
}

export class TestItemHost extends webhubElement {
  @observable items: Array<{ name: string }> = [
    { name: 'Alpha' },
    { name: 'Beta' },
    { name: 'Gamma' },
  ];

  @observable condData = { showHeader: true, label: 'Hello' };

  replaceItems(): void {
    this.items = [{ name: 'One' }, { name: 'Two' }];
  }

  clearItems(): void {
    this.items = [];
  }

  hideCondHeader(): void {
    this.condData = { ...this.condData, showHeader: false };
  }
}

TestItemList.define('test-item-list');
TestCondChild.define('test-cond-child');
TestItemHost.define('test-item-host');
