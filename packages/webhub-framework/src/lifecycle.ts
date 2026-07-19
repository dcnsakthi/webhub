// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * Hydration lifecycle tracker.
 *
 * Tracks aggregate hydration timing via the Performance API and fires a
 * global `webhub:hydration-complete` event on `window` once every registered
 * component has finished hydrating.
 *
 * ## Performance marks
 *
 * Global:
 * - `webhub:hydrate:total:start`  — first component begins hydrating
 * - `webhub:hydrate:total:end`    — last component finishes
 * - measure `webhub:hydrate:total`
 *
 * ## Window event
 *
 * `webhub:hydration-complete` — dispatched once on `window` when all
 * components are hydrated.
 */

/** How many components are still waiting to hydrate. */
let pendingCount = 0;

/** Whether the global start mark has been placed. */
let started = false;

/** Whether the global complete event has already fired. */
let completed = false;

/**
 * Call before a component begins hydration.
 * Increments the pending counter and (once) places the global start mark.
 */
export function hydrationStart(): void {
  if (!started) {
    performance.mark('webhub:hydrate:total:start');
    started = true;
  }
  pendingCount++;
}

/**
 * Call after a component has finished hydration.
 * When the last component finishes, fires the global event + measure.
 */
export function hydrationEnd(): void {
  pendingCount--;

  if (pendingCount <= 0 && !completed) {
    completed = true;
    performance.mark('webhub:hydrate:total:end');
    performance.measure(
      'webhub:hydrate:total',
      'webhub:hydrate:total:start',
      'webhub:hydrate:total:end',
    );
    window.dispatchEvent(new Event('webhub:hydration-complete'));
  }
}
