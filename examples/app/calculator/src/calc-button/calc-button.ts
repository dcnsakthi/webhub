// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, attr } from '@microsoft/webhub-framework';

export class CalcButton extends webhubElement {
  @attr label = '';
  @attr value = '';
  @attr btnType = '';
  @attr btnSpan = '';

  onClick(): void {
    this.$emit('button-press', { value: this.value });
  }
}

CalcButton.define('calc-button');
