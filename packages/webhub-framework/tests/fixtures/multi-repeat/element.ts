// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '../../../src/index.js';

interface MultiRepeatItem {
  title: string;
  href: string;
  active: string;
}

export class TestMultiRepeat extends webhubElement {
  @observable items: MultiRepeatItem[] = [
    { title: 'Alpha', href: '/alpha', active: 'true' },
    { title: 'Beta', href: '/beta', active: 'false' },
  ];
}

TestMultiRepeat.define('test-multi-repeat');
