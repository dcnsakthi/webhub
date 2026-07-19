// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { webhubElement, observable } from '@microsoft/webhub-framework';
import type { RouteLoaderContext } from '@microsoft/webhub-router';

export class PageLoader extends webhubElement {
  @observable source = '';
  @observable loaderMessage = '';

  static async loader(_ctx: RouteLoaderContext): Promise<Record<string, unknown>> {
    return {
      source: 'client-loader',
      loaderMessage: 'Data fetched by static loader',
    };
  }
}
