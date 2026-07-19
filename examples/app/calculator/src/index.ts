// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * Calculator hydration entry point.
 *
 * The server pre-renders HTML with hydration markers via `webhub build --plugin=webhub`.
 * Registered custom elements hydrate through webhub Framework. Scriptless
 * components remain SSR-only.
 */

window.addEventListener('webhub:hydration-complete', logHydrationTiming);

function logHydrationTiming(): void {
  const total = performance.getEntriesByName('webhub:hydrate:total', 'measure')[0];
  if (total) {
    console.log(`Calculator hydration complete in ${total.duration.toFixed(1)}ms`);
  }
}

// Side-effect imports — register custom elements and trigger hydration.
import './calc-app/calc-app.js';
import './calc-button/calc-button.js';

// Fallback: if hydration already completed before the listener, log now
if (performance.getEntriesByName('webhub:hydrate:total', 'measure').length > 0) {
  logHydrationTiming();
}
