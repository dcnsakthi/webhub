// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '@microsoft/webhub-framework';

export class PageDetail extends webhubElement {
  @observable itemId = '';
}
