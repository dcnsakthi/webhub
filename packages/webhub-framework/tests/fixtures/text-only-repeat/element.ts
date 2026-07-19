// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '../../../src/index.js';

interface Option {
  title: string;
  active: boolean;
}

export class TestTextOnlyRepeat extends webhubElement {
  @observable options: Option[] = [];

  onUpdate(): void {
    // Shift active from first to second option
    this.options = this.options.map((opt, i) => ({
      ...opt,
      active: i === 1,
    }));
  }
}

TestTextOnlyRepeat.define('test-text-only-repeat');
