// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '../../../src/index.js';

export class TestLifecycleChild extends webhubElement {
  @observable value: string | null | undefined = undefined;
  @observable connectedValue = '';
  @observable fallbackApplied = 'no';

  connectedCallback(): void {
    super.connectedCallback();
    this.connectedValue = this.value ?? '<unset>';
    if (this.value === null || this.value === undefined) {
      this.value = 'set-by-child';
      this.fallbackApplied = 'yes';
    } else {
      this.fallbackApplied = 'no';
    }
  }
}

export class TestLifecycleParent extends webhubElement {
  @observable val: string | undefined = undefined;

  setParentValue(value: string): void {
    this.val = value;
  }
}

export class TestLifecycleConditionalParent extends webhubElement {
  @observable show = false;
  @observable val: string | undefined = undefined;

  showChild(): void {
    this.show = true;
  }
}

export class TestLifecycleRepeatParent extends webhubElement {
  @observable items: Array<{ id: string; value?: string }> = [];

  setItems(items: Array<{ id: string; value?: string }>): void {
    this.items = items;
  }
}

export class TestLifecycleConditionalRepeatParent extends webhubElement {
  @observable show = false;
  @observable items: Array<{ id: string; value?: string }> = [];

  showItems(items: Array<{ id: string; value?: string }>): void {
    this.items = items;
    this.show = true;
  }
}

export class TestLifecycleNestedRepeatParent extends webhubElement {
  @observable groups: Array<{ id: string; items: Array<{ id: string; value?: string }> }> = [];

  setGroups(groups: Array<{ id: string; items: Array<{ id: string; value?: string }> }>): void {
    this.groups = groups;
  }
}

export class TestLifecycleKeyedNestedRepeatParent extends webhubElement {
  @observable groups: Array<{ id: string; items: Array<{ id: string; value?: string }> }> = [];

  setGroups(groups: Array<{ id: string; items: Array<{ id: string; value?: string }> }>): void {
    this.groups = groups;
  }
}

TestLifecycleChild.define('test-lifecycle-child');
TestLifecycleParent.define('test-lifecycle-parent');
TestLifecycleConditionalParent.define('test-lifecycle-conditional-parent');
TestLifecycleRepeatParent.define('test-lifecycle-repeat-parent');
TestLifecycleConditionalRepeatParent.define('test-lifecycle-conditional-repeat-parent');
TestLifecycleNestedRepeatParent.define('test-lifecycle-nested-repeat-parent');
TestLifecycleKeyedNestedRepeatParent.define('test-lifecycle-keyed-nested-repeat-parent');
