// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/**
 * Minimal template registration utilities for E2E test fixtures.
 *
 * Most fixtures now use real webhub HTML templates compiled by the pipeline
 * (see fixture-render.ts). These helpers remain for edge cases that need
 * programmatic template registration (e.g. light-DOM hydration tests,
 * client-created component tests).
 */

import type {
  CompiledConditionFn,
  TemplateMeta,
} from '../../webhub-framework/src/template-types.js';

export type { CompiledConditionFn, TemplateMeta };

/**
 * Register a compiled template so the framework can hydrate or mount
 * a custom element with the given tag name.
 */
export function registerCompiledTemplate(
  name: string,
  meta: TemplateMeta,
  fns?: CompiledConditionFn[],
): void {
  const w = window as unknown as {
    __webhub?: {
      templates?: Record<string, TemplateMeta>;
      templateFns?: Record<string, CompiledConditionFn[]>;
      [k: string]: unknown;
    };
  };
  if (!w.__webhub) w.__webhub = {};
  if (!w.__webhub.templates) w.__webhub.templates = {};
  w.__webhub.templates[name] = meta;
  if (fns) {
    if (!w.__webhub.templateFns) w.__webhub.templateFns = {};
    w.__webhub.templateFns[name] = fns;
  }
}

/** Render a static template registration as an inline `<script>` tag. */
export function renderTemplateScript(name: string, meta: TemplateMeta): string {
  return `<script>window.__webhub=window.__webhub||{};window.__webhub.templates=window.__webhub.templates||{};window.__webhub.templates[${JSON.stringify(name)}]=${JSON.stringify(meta)};</script>`;
}
