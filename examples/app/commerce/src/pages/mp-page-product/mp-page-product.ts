// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '@microsoft/webhub-framework';

import '#organisms/mp-product-gallery/mp-product-gallery.js';
import '#organisms/mp-variant-selector/mp-variant-selector.js';
import '#organisms/mp-add-to-cart/mp-add-to-cart.js';
import '#organisms/mp-product-card/mp-product-card.js';

export class MpPageProduct extends webhubElement {
  @observable selectedColor!: string;
  @observable selectedSize!: string;

  onVariantSelect(event: Event): void {
    const { group, value } = (event as CustomEvent).detail;
    const name = (group as string).trim().toLowerCase();
    if (name.includes('color')) this.selectedColor = value;
    else if (name.includes('size')) this.selectedSize = value;
  }
}

MpPageProduct.define('mp-page-product');
