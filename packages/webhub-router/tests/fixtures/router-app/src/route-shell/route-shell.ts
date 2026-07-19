// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '@microsoft/webhub-framework';

export class RouteShell extends webhubElement {
  @observable isHome = false;
  @observable isAlpha = false;
  @observable isBeta = false;
  @observable isItem1 = false;
  @observable isItem2 = false;
}
