// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '@microsoft/webhub-framework';

export class ErrorDisplay extends webhubElement {
  @observable errorMessage = '';
  @observable errorPath = '';

  onRetry = (): void => {
    window.navigation.navigate('/');
  };
}
