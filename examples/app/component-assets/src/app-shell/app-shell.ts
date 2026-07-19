// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, attr } from '@microsoft/webhub-framework';
import { defineComponentAssets } from '@microsoft/webhub-framework/component-asset.js';

const assets = defineComponentAssets({
  'lazy-panel': {
    asset: './lazy-panel.webhub.js',
    data: async () => await (await fetch('./lazy-panel-data.json')).json(),
  },
});

export class AppShell extends webhubElement {
  @attr title = '';

  panelSlot!: HTMLDivElement;

  async openPanel(): Promise<void> {
    this.panelSlot.replaceChildren(await assets.create('lazy-panel'));
  }
}

AppShell.define('app-shell');
