// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * @microsoft/webhub-router — DOM-native client-side router for webhub apps.
 *
 * Routes are `<webhub-route>` custom elements (transformed from `<route>` at build time).
 * The router uses the Navigation API to intercept navigations and show/hide matching routes.
 *
 * @example
 * ```ts
 * import { Router } from '@microsoft/webhub-router';
 * Router.start();
 * Router.navigate('/contacts/42');
 * ```
 *
 * @packageDocumentation
 */

export { Router, webhubRouter } from './router.js';
export { webhubRouteElement, parseQuery, filterQuery } from './route-element.js';
export { isStateful } from './types.js';
export type {
  RouterConfig,
  NavigationEvent,
  RouteLoaderContext,
  CacheConfig,
  RouteActionContext,
  RouteActionResult,
  ActionCompleteEvent,
  StatefulElement,
} from './types.js';
