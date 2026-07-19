// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '../../../src/index.js';

interface SplitRepeatItem {
  label: string;
}

export class TestSplitRepeat extends webhubElement {
  @observable primaryItems: SplitRepeatItem[] = [{ label: 'Seed Alpha' }, { label: 'Seed Beta' }];
  @observable secondaryItems: SplitRepeatItem[] = [{ label: 'Seed One' }, { label: 'Seed Two' }];

  loadItems(): void {
    this.primaryItems = [{ label: 'Alpha' }, { label: 'Beta' }];
    this.secondaryItems = [{ label: 'One' }, { label: 'Two' }, { label: 'Three' }];
  }
}

TestSplitRepeat.define('test-split-repeat');

