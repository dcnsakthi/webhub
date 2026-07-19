// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '../../../src/index.js';

export class TestRawHtml extends webhubElement {
  @observable expanded = true;
  @observable name = '';
  @observable rawHtml = '';
}

TestRawHtml.define('test-raw-html');
