// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '@microsoft/webhub-framework';

export class TestDialog extends webhubElement {
  @observable message = 'Hello from dialog';

  onClose(): void {
    this.$emit('close-dialog');
  }
}
TestDialog.define('test-dialog');
