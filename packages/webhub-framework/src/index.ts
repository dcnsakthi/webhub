// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * @microsoft/webhub-framework — lightweight Web Component runtime with SSR hydration.
 *
 * Provides a reactive base class, decorators, and hydration utilities for
 * building Web Components that work with webhub's server-side rendering pipeline.
 *
 * @example
 * ```ts
 * import { webhubElement, observable, attr } from '@microsoft/webhub-framework';
 *
 * class MyCounter extends webhubElement {
 *   @attr count = 0;
 *   @observable label = 'Count';
 * }
 * MyCounter.define('my-counter');
 * ```
 *
 * @packageDocumentation
 */

import { installTemplateElementRuntime } from './static-host.js';

setTimeout(installTemplateElementRuntime, 0);

export { webhubElement } from './element.js';
export { observable, attr } from './decorators.js';
export { getTemplate, registerTemplateData } from './template.js';
export type { TemplateMeta } from './template.js';
export { hydrationStart, hydrationEnd } from './lifecycle.js';
