// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '@microsoft/webhub-framework';

export class CbContactDetail extends webhubElement {
  @observable id!: string;
  @observable favorite!: boolean;

  onEdit(): void {
    this.$emit('edit-contact', { id: this.id });
  }

  onToggleFavorite(): void {
    this.favorite = !this.favorite;
    this.$emit('toggle-favorite', { id: this.id });
  }

  onDelete(): void {
    this.$emit('delete-contact', { id: this.id });
  }

  onGoBack(): void {
    this.$emit('go-back');
  }
}

CbContactDetail.define('cb-contact-detail');
