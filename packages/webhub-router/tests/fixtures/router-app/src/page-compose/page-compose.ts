// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, attr } from '@microsoft/webhub-framework';

export class PageCompose extends webhubElement {
  @attr action = '';
  @attr to = '';
  @attr subject = '';
}
