// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! webhub Handler implementation for Rust.
//!
//! This crate provides functionality to process and render webhub protocols
//! into final HTML output based on provided data.

pub mod css_module;
pub(crate) mod html_encode;
pub mod plugin;
pub mod route_handler;
pub mod route_matcher;
pub(crate) mod route_renderer;

pub use route_handler::Protocol;

/// Minimal HTML escaper for the 6 XSS-critical characters
/// (`& < > " ' /`). Returns `Cow::Borrowed` when no escaping is
/// needed (zero allocation on the happy path), `Cow::Owned` when
/// any character had to be replaced.
///
/// Re-exported here so external callers of `RenderOptions::with_head_inject`
/// / `with_body_inject` can pre-escape untrusted content with the
/// same escaper the handler uses internally for SSR text content,
/// without having to pull in a separate HTML-escape crate.
pub use html_encode::encode_safe;

use plugin::BootstrapExtensionContext;
use plugin::HandlerPlugin;
use plugin::webhubTemplatePayload;
use route_matcher::CompiledRouteIndex;
use serde::ser::SerializeMap;
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use webhub_expressions::{evaluate_with_resolver, ExpressionError};
use webhub_protocol::{
    web_ui_fragment::Fragment, InitialStateStrategy, StateProjectionMode, webhubFragment,
    webhubProtocol,
};
use webhub_state::find_value_by_dotted_path_ref;

/// Error types for the webhub handler.
#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("Rendering error: {0}")]
    Rendering(String),

    #[error("Rendering invariant error: {0}")]
    Invariant(String),

    #[error("Missing fragment: {0}")]
    MissingFragment(String),

    #[error("Missing data field: {0}")]
    MissingData(String),

    #[error("Type error: {0}")]
    TypeError(String),

    #[error("Protocol error: {0}")]
    Protocol(#[from] webhub_protocol::ProtocolError),

    #[error("Evaluation error: {0}")]
    Evaluation(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Writer error: {0}")]
    Writer(String),

    #[error("Plugin data error: {0}")]
    PluginData(String),

    /// The HTTP client disconnected before the render completed.
    ///
    /// Streaming `ResponseWriter` implementations return this from
    /// `write()` once their channel/socket is closed, so the handler
    /// can abort the render rather than do CPU work that has nowhere
    /// to go. Allocation-free (the variant carries no payload).
    #[error("client disconnected")]
    ClientDisconnected,

    /// The streaming writer's flush exceeded its configured deadline.
    ///
    /// Indicates a slow/unresponsive consumer (slow-loris client,
    /// stuck proxy, etc.). The render thread is freed; downstream
    /// telemetry should distinguish this from `ClientDisconnected`
    /// so ops can alert on slow-client attacks.
    #[error("streaming flush timed out")]
    StreamTimeout,
}

pub type Result<T> = std::result::Result<T, HandlerError>;

/// Interface for writing rendered output
pub trait ResponseWriter {
    /// Write content to the output
    fn write(&mut self, content: &str) -> Result<()>;

    /// Finalize the output
    fn end(&mut self) -> Result<()>;
}

/// Options controlling how the handler renders a protocol.
///
/// The handler performs server-side route matching: matched routes are rendered
/// visible with content; non-matched routes are rendered hidden and empty.
pub struct RenderOptions<'a> {
    /// The fragment ID to start rendering from (e.g., `"index.html"`).
    pub entry_id: &'a str,
    /// The URL path to match routes against (e.g., `"/contacts/42"`).
    pub request_path: &'a str,
    /// Optional CSP nonce for inline `<script>` tags.
    /// When set, all inline scripts include `nonce="VALUE"` and a
    /// `<meta name="webhub-nonce">` tag is emitted for the client router.
    pub nonce: Option<&'a str>,
    /// Optional HTML to emit immediately before the document's
    /// `</head>` close. Used for per-request `<link rel="preload">`
    /// hints, CSP `<meta>` tags beyond the built-in nonce, etc.
    /// Inserted at the structural `head_end` boundary identified by
    /// the parser — never matched against a byte pattern, so cannot
    /// be tricked by `</head>` literals appearing in HTML comments,
    /// `srcdoc` attributes, or inline scripts.
    pub head_inject: Option<&'a str>,
    /// Optional HTML to emit immediately before the document's
    /// `</body>` close. Used for dev livereload `<script>`, analytics
    /// snippets, OpenTelemetry trace IDs, etc.
    /// Same structural-boundary guarantee as [`head_inject`](Self::head_inject).
    pub body_inject: Option<&'a str>,
}

impl<'a> RenderOptions<'a> {
    /// Create render options for the given entry fragment and request path.
    #[must_use]
    pub fn new(entry_id: &'a str, request_path: &'a str) -> Self {
        Self {
            entry_id,
            request_path,
            nonce: None,
            head_inject: None,
            body_inject: None,
        }
    }

    /// Set the CSP nonce for inline scripts. Pass an empty string to
    /// disable (`None` semantics) — empty `<meta name="webhub-nonce"
    /// content="">` would be browser-ignored noise.
    #[must_use]
    pub fn with_nonce(mut self, nonce: &'a str) -> Self {
        self.nonce = if nonce.is_empty() { None } else { Some(nonce) };
        self
    }

    /// Set HTML to emit immediately before `</head>`.
    /// Pass an empty string to disable (`None` semantics).
    ///
    /// # Safety (XSS warning)
    ///
    /// The provided HTML is written verbatim — **no HTML escaping is
    /// performed**. Callers MUST ensure the content is fully trusted
    /// (typically a `&'static str` or build-time-derived bytes such as
    /// dev livereload script, image preload `<link>` tags, or A/B test
    /// markers). Passing user-controlled or attacker-influenced content
    /// here is a direct cross-site scripting vulnerability. If your
    /// caller path may include untrusted data, escape with the host's
    /// HTML escaper (e.g. [`webhub_handler::encode_safe`](crate::encode_safe))
    /// **before** calling this builder.
    #[must_use]
    pub fn with_head_inject(mut self, html: &'a str) -> Self {
        self.head_inject = if html.is_empty() { None } else { Some(html) };
        self
    }

    /// Set HTML to emit immediately before `</body>`.
    /// Pass an empty string to disable (`None` semantics).
    ///
    /// # Safety (XSS warning)
    ///
    /// Same contract as [`with_head_inject`](Self::with_head_inject):
    /// the HTML is written verbatim with **no escaping**, so callers
    /// MUST ensure the content is fully trusted. Untrusted content is
    /// a direct XSS vector.
    #[must_use]
    pub fn with_body_inject(mut self, html: &'a str) -> Self {
        self.body_inject = if html.is_empty() { None } else { Some(html) };
        self
    }
}

/// The main webhub handler that processes protocols and renders them.
///
/// The handler is stateless: plugin instances are created per-render from
/// the stored factory function, allowing concurrent renders with `&self`.
pub struct webhubHandler {
    plugin_factory: Option<fn() -> Box<dyn HandlerPlugin>>,
}

/// Context object for processing webhub fragments
struct webhubProcessContext<'a> {
    protocol: &'a webhubProtocol,
    state: &'a Value,
    writer: &'a mut dyn ResponseWriter,
    local_vars: HashMap<String, Value>,
    /// Accumulates component attribute values between attrStart and the component fragment.
    component_attrs: HashMap<String, Value>,
    /// URL path for server-side route matching. Borrowed from
    /// `RenderOptions<'a>::request_path` — zero-copy.
    request_path: &'a str,
    /// Base path for resolving relative route paths (`./`).
    /// Updated as the handler descends into nested matched routes.
    /// `Cow` keeps the initial `"/"` literal zero-copy; nested-route
    /// descent owns the recomputed path.
    route_base: Cow<'a, str>,
    /// Component names visited during rendering (for selective f-template emission
    /// and CSS module dedup — only the first render of each component emits
    /// its `<script type="importmap">` data-URI tag).
    rendered_components: HashSet<String>,
    /// Per-render plugin instance created from the handler's factory.
    plugin: Option<Box<dyn HandlerPlugin>>,
    /// Current position in the route tree for outlet-based rendering.
    /// Contains the children of the currently matched route fragment.
    route_children: Vec<webhub_protocol::webhubFragmentRoute>,
    /// Entry fragment ID — used to compute the initial inventory at head_end.
    /// Borrowed from `RenderOptions<'a>::entry_id` — zero-copy.
    entry_id: &'a str,
    /// CSP nonce for inline `<script>` tags (None = no nonce attribute).
    /// Borrowed from `RenderOptions<'a>::nonce` — zero-copy.
    nonce: Option<&'a str>,
    /// Component-name → bit-position map built once when the runtime
    /// [`Protocol`] is created and shared by every render.
    component_index: &'a HashMap<String, u32>,
    /// HTML emitted at the structural `head_end` boundary (before
    /// `</head>`), after the built-in nonce/CSS-preload emissions.
    /// Zero-copy borrow of the caller's `RenderOptions<'a>::head_inject`
    /// (no per-render clone — saves an allocation when the host passes
    /// a `&'static str` such as a dev livereload script).
    head_inject: Option<&'a str>,
    /// HTML emitted at the structural `body_end` boundary (before
    /// `</body>`), after the built-in template metadata emissions.
    /// Same zero-copy borrow as [`head_inject`](Self::head_inject).
    body_inject: Option<&'a str>,
    /// Tracks whether the `head_end` hook has already fired in this
    /// render. Defends against malformed protocols that emit the
    /// signal more than once (e.g., a template with multiple `<head>`
    /// tags) — without this, host-supplied `head_inject` HTML, CSS
    /// preload `<link>` tags, and the CSP `<meta>` nonce would be
    /// duplicated, which can be a CSP-bypass / cache-bloat vector.
    head_end_emitted: bool,
    /// Tracks whether the `body_end` hook has already fired in this
    /// render. Defends against malformed protocols emitting the
    /// signal twice — without this, hydration `<script>` blocks and
    /// host-supplied `body_inject` would be duplicated.
    body_end_emitted: bool,
    /// Immutable authored route patterns compiled when [`Protocol`] is loaded.
    route_index: &'a CompiledRouteIndex,
    /// Counter for `data-ri` attributes on matched route elements.
    /// Incremented each time a matched route is rendered, allowing O(1) element
    /// binding on the client side instead of DOM-walking.
    route_chain_index: usize,
}

struct webhubBootstrap<'a> {
    state: &'a Value,
    state_selection: StateSelection<'a>,
    chain: &'a [Value],
    inventory: &'a str,
    nonce: Option<&'a str>,
    css_hrefs: &'a [&'a str],
    style_specs: &'a [&'a str],
    templates: &'a [webhubTemplatePayload<'a>],
}

/// Get the component attribute name, stripping `:` prefix and converting to camelCase.
///
/// Uses `webhub_protocol::attrs::attribute_to_camel` which handles irregular
/// attributes (multi-word ARIA and global HTML attributes like `readonly`,
/// `tabindex`) via the shared lookup table.
fn component_attr_name(name: &str) -> String {
    let stripped = name.strip_prefix(':').unwrap_or(name);
    webhub_protocol::attrs::attribute_to_camel(stripped)
}

/// Write a usize as decimal digits directly to the writer, avoiding `format!` allocation.
fn write_usize(writer: &mut dyn ResponseWriter, mut n: usize) -> Result<()> {
    if n == 0 {
        return writer.write("0");
    }
    // Max digits for a 64-bit usize is 20.
    let mut buf = [0u8; 20];
    let mut pos = buf.len();
    while n > 0 {
        pos -= 1;
        // n % 10 is always in 0..=9, fits in u8 without truncation.
        #[allow(clippy::cast_possible_truncation)]
        let digit = (n % 10) as u8;
        buf[pos] = b'0' + digit;
        n /= 10;
    }
    // Digits are always valid ASCII/UTF-8.
    match std::str::from_utf8(&buf[pos..]) {
        Ok(s) => writer.write(s),
        Err(_) => writer.write("0"),
    }
}

pub(crate) fn write_script_safe_json<T>(writer: &mut dyn ResponseWriter, value: &T) -> Result<()>
where
    T: Serialize + ?Sized,
{
    let mut json = Vec::with_capacity(256);
    serde_json::to_writer(&mut json, value)
        .map_err(|error| HandlerError::Rendering(format!("failed to serialize JSON: {error}")))?;
    let json = std::str::from_utf8(&json)
        .map_err(|error| HandlerError::Rendering(format!("invalid JSON UTF-8: {error}")))?;
    write_script_safe_json_str(writer, json)
}

fn write_script_safe_json_str(writer: &mut dyn ResponseWriter, json: &str) -> Result<()> {
    let mut start = 0;
    while start < json.len() {
        let rest = &json[start..];
        let Some(offset) = rest.find("</") else {
            writer.write(rest)?;
            return Ok(());
        };

        if offset > 0 {
            writer.write(&rest[..offset])?;
        }
        writer.write("<\\/")?;
        start += offset + 2;
    }
    Ok(())
}

fn write_json_field_name(
    writer: &mut dyn ResponseWriter,
    wrote_field: &mut bool,
    name: &str,
) -> Result<()> {
    if *wrote_field {
        writer.write(",")?;
    }
    *wrote_field = true;
    writer.write("\"")?;
    writer.write(name)?;
    writer.write("\":")
}

fn write_json_field<T>(
    writer: &mut dyn ResponseWriter,
    wrote_field: &mut bool,
    name: &str,
    value: &T,
) -> Result<()>
where
    T: Serialize + ?Sized,
{
    write_json_field_name(writer, wrote_field, name)?;
    write_script_safe_json(writer, value)
}

/// Serialize wrapper that projects an SSR state object down to only the
/// keys present in the build-time hydration allowlist.
///
/// This is the runtime half of the projected-hydration design: instead of
/// serializing the entire application state (potentially megabytes) on every
/// full-HTML render, only the fields a component actually hydrates are
/// emitted. The request allowlist conservatively includes every reachable
/// component's hydration keys so no field a component needs is dropped.
///
/// Projection is a payload boundary, not a secrecy boundary. Any key selected
/// by compiled client metadata is browser-facing, so hosts must never place
/// secrets in browser render state.
///
/// `keys` MUST be sorted and deduplicated. Projection iterates whichever side
/// is smaller: hydration keys with direct map lookup for wide states, or state
/// entries with binary-search membership for compact states. Non-object states
/// carry nothing hydratable and serialize as an empty object.
struct ProjectedState<'a> {
    value: &'a Value,
    keys: &'a [&'a str],
}

impl Serialize for ProjectedState<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let Value::Object(map) = self.value else {
            return serializer.serialize_map(Some(0))?.end();
        };

        let mut out = serializer.serialize_map(None)?;
        if self.keys.len() < map.len() {
            let mut previous = None;
            for key in self.keys {
                if previous == Some(*key) {
                    continue;
                }
                previous = Some(*key);
                if let Some(value) = map.get(*key) {
                    out.serialize_entry(key, value)?;
                }
            }
        } else {
            for (key, value) in map {
                if self
                    .keys
                    .binary_search_by(|candidate| candidate.cmp(&key.as_str()))
                    .is_ok()
                {
                    out.serialize_entry(key, value)?;
                }
            }
        }
        out.end()
    }
}

/// Write the SSR `state` into the bootstrap block according to the protocol's
/// build-time selection and escape it for safe embedding in a `<script>`.
///
/// [`ProjectedState`] serializes only the allowlisted keys, so for the typical
/// payload — a large state with a small hydratable surface — serde ever only
/// touches the projected subset. Serialization reuses the proven
/// [`write_script_safe_json`] path (serde's fast `Vec<u8>` target plus a single
/// SIMD-accelerated `</` escape pass), which matches the pre-projection cost
/// when every key is hydratable and collapses to a few bytes when it is not.
/// Buffering the projected bytes and escaping once is measurably faster than
/// streaming through a per-token `io::Write` adapter, and the projected buffer
/// is tiny in the common case.
fn write_selected_state(
    writer: &mut dyn ResponseWriter,
    state: &Value,
    selection: &StateSelection<'_>,
) -> Result<()> {
    let StateSelection::Keys(keys) = selection else {
        return write_script_safe_json(writer, state);
    };
    if keys.is_empty() {
        return writer.write("{}");
    }

    // Projection membership may use binary search, so a mis-sorted key set
    // would silently drop hydration keys. The key allowlist is produced sorted +
    // deduped at build time; this guard makes hand-built protocols that violate
    // the invariant fail loudly in tests at zero release cost.
    debug_assert!(
        keys.windows(2).all(|pair| pair[0] <= pair[1]),
        "hydration keys must be sorted for binary-search projection"
    );
    if let Value::Object(map) = state {
        let selects_entire_map =
            keys.len() == map.len() && keys.iter().copied().eq(map.keys().map(String::as_str));
        if selects_entire_map {
            return write_script_safe_json(writer, state);
        }
    }
    write_script_safe_json(writer, &ProjectedState { value: state, keys })
}

// Covers the common route surface without trusting protocol-derived counts for
// an eager allocation; larger key sets grow only as actual keys are visited.
const INITIAL_KEY_CAPACITY: usize = 16;

/// Request-scoped state selection derived from reachable component metadata.
pub(crate) enum StateSelection<'a> {
    /// Preserve the complete state value.
    Full,
    /// Project an object to a sorted, deduplicated key allowlist.
    Keys(Vec<&'a str>),
}

enum ComponentStateSurface {
    Hydration,
    Navigation,
}

/// Select initial state for the components reachable on this request path.
///
/// Non-webhub protocols preserve full state without walking component surfaces.
/// webhub protocols project exact surfaces, while any unknown surface restores
/// the full state for correctness.
pub(crate) fn collect_hydration_state<'a, 'b>(
    protocol: &'a webhubProtocol,
    components: impl IntoIterator<Item = &'b str>,
) -> StateSelection<'a> {
    if protocol.initial_state_strategy != InitialStateStrategy::Components as i32 {
        return StateSelection::Full;
    }
    collect_component_state(protocol, components, ComponentStateSurface::Hydration)
}

/// Select state for client-created components reachable during navigation.
pub(crate) fn collect_navigation_state<'a, 'b>(
    protocol: &'a webhubProtocol,
    components: impl IntoIterator<Item = &'b str>,
) -> StateSelection<'a> {
    collect_component_state(protocol, components, ComponentStateSurface::Navigation)
}

fn collect_component_state<'a, 'b>(
    protocol: &'a webhubProtocol,
    components: impl IntoIterator<Item = &'b str>,
    surface: ComponentStateSurface,
) -> StateSelection<'a> {
    let mut keys = Vec::with_capacity(INITIAL_KEY_CAPACITY);
    for name in components {
        let Some(component) = protocol.components.get(name) else {
            return StateSelection::Full;
        };
        let (mode, component_keys) = match surface {
            ComponentStateSurface::Hydration => {
                (component.hydration_mode, &component.hydration_keys)
            }
            ComponentStateSurface::Navigation => {
                (component.navigation_mode, &component.navigation_keys)
            }
        };
        if mode == StateProjectionMode::All as i32 {
            return StateSelection::Full;
        }
        if mode == StateProjectionMode::Keys as i32
            || (mode == StateProjectionMode::None as i32 && !component_keys.is_empty())
        {
            keys.extend(component_keys.iter().map(String::as_str));
        } else if mode != StateProjectionMode::None as i32 {
            return StateSelection::Full;
        }
    }
    keys.sort_unstable();
    keys.dedup();
    StateSelection::Keys(keys)
}

fn write_webhub_bootstrap(
    writer: &mut dyn ResponseWriter,
    bootstrap: webhubBootstrap<'_>,
) -> Result<()> {
    let mut wrote_field = false;

    writer.write("{")?;
    if !bootstrap.chain.is_empty() {
        write_json_field(writer, &mut wrote_field, "chain", bootstrap.chain)?;
    }
    if !bootstrap.css_hrefs.is_empty() {
        write_json_field(writer, &mut wrote_field, "css", bootstrap.css_hrefs)?;
    }
    write_json_field(writer, &mut wrote_field, "inventory", bootstrap.inventory)?;
    if let Some(nonce) = bootstrap.nonce {
        write_json_field(writer, &mut wrote_field, "nonce", nonce)?;
    }
    write_json_field_name(writer, &mut wrote_field, "state")?;
    write_selected_state(writer, bootstrap.state, &bootstrap.state_selection)?;
    if !bootstrap.style_specs.is_empty() {
        write_json_field(writer, &mut wrote_field, "styles", bootstrap.style_specs)?;
    }
    if bootstrap
        .templates
        .iter()
        .any(|template| !template.template_json.is_empty())
    {
        write_json_field_name(writer, &mut wrote_field, "templates")?;
        write_webhub_template_json_map(writer, bootstrap.templates)?;
    }
    writer.write("}")
}

fn write_webhub_data_block(
    writer: &mut dyn ResponseWriter,
    bootstrap: webhubBootstrap<'_>,
) -> Result<()> {
    writer.write("<script type=\"application/json\" id=\"webhub-data\"")?;
    if let Some(nonce) = bootstrap.nonce {
        writer.write(" nonce=\"")?;
        writer.write(nonce)?;
        writer.write("\"")?;
    }
    writer.write(">")?;
    write_webhub_bootstrap(writer, bootstrap)?;
    writer.write("</script>\n")
}

fn write_webhub_template_json_map(
    writer: &mut dyn ResponseWriter,
    templates: &[webhubTemplatePayload<'_>],
) -> Result<()> {
    writer.write("{")?;
    let mut wrote = false;
    for template in templates {
        if template.template_json.is_empty() {
            continue;
        }
        if wrote {
            writer.write(",")?;
        }
        wrote = true;
        write_script_safe_json(writer, template.tag_name)?;
        writer.write(":")?;
        write_script_safe_json_str(writer, template.template_json)?;
    }
    writer.write("}")
}

fn resolve_value_from_sources<'ctx, 'state>(
    path: &str,
    local_vars: &'ctx HashMap<String, Value>,
    state: &'state Value,
) -> Option<Cow<'ctx, Value>>
where
    'state: 'ctx,
{
    if let Some(first_part) = path.split('.').next() {
        if let Some(local_value) = local_vars.get(first_part) {
            if first_part.len() == path.len() {
                return Some(Cow::Borrowed(local_value));
            }
            let remaining = &path[first_part.len() + 1..];
            if let Some(value) = find_value_by_dotted_path_ref(remaining, local_value) {
                return Some(value);
            }
        }
    }

    find_value_by_dotted_path_ref(path, state)
}

impl webhubHandler {
    /// Create a new webhub handler with no plugin.
    pub fn new() -> Self {
        Self {
            plugin_factory: None,
        }
    }

    /// Create a new webhub handler with a plugin factory.
    ///
    /// Each render call creates a fresh plugin instance from the factory,
    /// enabling concurrent renders with `&self`.
    pub fn with_plugin(factory: fn() -> Box<dyn HandlerPlugin>) -> Self {
        Self {
            plugin_factory: Some(factory),
        }
    }

    #[cfg(test)]
    fn handle(
        &self,
        document: &webhubProtocol,
        state: &Value,
        options: &RenderOptions<'_>,
        writer: &mut dyn ResponseWriter,
    ) -> Result<()> {
        let protocol = Protocol::new(document.clone());
        self.render(&protocol, state, options, writer)
    }

    /// Process a fragment by its ID.
    ///
    /// The `context` parameter contains scope-local variables that are accessible during rendering,
    /// such as loop iteration variables. This is separate from the global `state`.
    fn process_fragment_id(
        &self,
        fragment_id: &str,
        context: &mut webhubProcessContext,
    ) -> Result<()> {
        if let Some(fragment_list) = context.protocol.fragments.get(fragment_id) {
            self.process_fragment(&fragment_list.fragments, context)
        } else {
            Err(HandlerError::MissingFragment(fragment_id.to_string()))
        }
    }

    /// Process a vector of fragments.
    ///
    /// The `context` maintains scope-specific variables that can be accessed by fragments
    /// during rendering, while `state` contains the global application state.
    fn process_fragment(
        &self,
        fragments: &[webhubFragment],
        context: &mut webhubProcessContext,
    ) -> Result<()> {
        // Pre-scan: find the best matching route among sibling routes by specificity.
        // This ensures `/contacts/add` (2 literals) beats `/contacts/:id` (1 literal).
        // Resolves relative paths (`./`) using the current route_base.
        let best_route = route_renderer::find_best_route_match(
            fragments,
            context.request_path,
            &context.route_base,
            context.route_index,
        );

        for item in fragments {
            match item.fragment.as_ref() {
                Some(Fragment::Raw(raw)) => {
                    context.writer.write(&raw.value)?;
                }
                Some(Fragment::Component(component)) => {
                    self.process_component(component, context)?;
                }
                Some(Fragment::ForLoop(for_loop)) => {
                    self.process_for_loop(for_loop, context)?;
                }
                Some(Fragment::Signal(signal)) => {
                    self.process_signal(signal, context)?;
                }
                Some(Fragment::IfCond(if_cond)) => {
                    self.process_if(if_cond, context)?;
                }
                Some(Fragment::Attribute(attr)) => {
                    self.process_attribute(attr, context)?;
                }
                Some(Fragment::Plugin(plugin_frag)) => {
                    if let Some(p) = &mut context.plugin {
                        p.on_element_data(&plugin_frag.data, context.writer)?;
                    }
                }
                Some(Fragment::Route(route_frag)) => {
                    self.process_route(route_frag, &best_route, context)?;
                }
                Some(Fragment::Outlet(_)) => {
                    self.process_outlet(context)?;
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Process an `<outlet />` directive.
    ///
    /// Matches children from the currently active route's `children` field
    /// against the request path, renders the matched child `<webhub-route>`
    /// elements directly at this position (no wrapper element).
    fn process_outlet(&self, context: &mut webhubProcessContext) -> Result<()> {
        let mut children = std::mem::take(&mut context.route_children);
        if children.is_empty() {
            return Ok(());
        }

        // Find the best matching child route
        let request_segments = route_matcher::split_request_path(context.request_path);
        let mut best: Option<(usize, route_matcher::RouteMatch)> = None;
        for (idx, child) in children.iter().enumerate() {
            if let Some(m) = route_matcher::match_route_indexed_with_segments(
                context.route_index,
                &child.path,
                &context.route_base,
                &request_segments,
                child.exact,
            ) {
                let is_better = best
                    .as_ref()
                    .is_none_or(|(_, prev)| m.specificity > prev.specificity);
                if is_better {
                    best = Some((idx, m));
                }
            }
        }

        // Extract grandchildren from the matched child to avoid cloning.
        // We swap out the children vec so we can move it into context without
        // cloning, then swap an empty vec back for the sibling rendering pass.
        let grandchildren = if let Some((idx, _)) = &best {
            std::mem::take(&mut children[*idx].children)
        } else {
            Vec::new()
        };

        if let Some((idx, ref rm)) = best {
            let matched_child = &children[idx];
            let comp = &matched_child.fragment_id;

            if !comp.is_empty() {
                let saved_route_base = context.route_base.clone();
                let saved_route_children = std::mem::take(&mut context.route_children);

                if rm.consumed_segments > 0 {
                    context.route_base = Cow::Owned(route_matcher::compute_route_base(
                        context.request_path,
                        rm.consumed_segments,
                    ));
                }

                context.route_children = grandchildren;

                // Emit matched <webhub-route>
                context.writer.write("<webhub-route")?;
                if !matched_child.path.is_empty() {
                    context.writer.write(" path=\"")?;
                    context.writer.write(&matched_child.path)?;
                    context.writer.write("\"")?;
                }
                context.writer.write(" component=\"")?;
                context.writer.write(comp)?;
                context.writer.write("\"")?;
                if matched_child.exact {
                    context.writer.write(" exact")?;
                }
                route_renderer::write_route_pending_attrs(context.writer, matched_child)?;
                // Emit data-ri for O(1) client-side element binding
                let ri = context.route_chain_index;
                context.route_chain_index += 1;
                context.writer.write(" data-ri=\"")?;
                write_usize(context.writer, ri)?;
                context.writer.write("\" active>")?;

                context.writer.write("<")?;
                context.writer.write(comp)?;
                if let Some(p) = &context.plugin {
                    p.write_route_component_state(context.state, context.writer)?;
                }
                context.writer.write(">")?;

                self.process_component(
                    &webhub_protocol::webhubFragmentComponent {
                        fragment_id: comp.clone(),
                    },
                    context,
                )?;

                context.writer.write("</")?;
                context.writer.write(comp)?;
                context.writer.write(">")?;
                context.writer.write("</webhub-route>")?;

                context.route_base = saved_route_base;
                context.route_children = saved_route_children;
            }
        }

        // Render non-matched siblings as hidden
        for (idx, child) in children.iter().enumerate() {
            let is_matched = best.as_ref().is_some_and(|(bi, _)| *bi == idx);
            if !is_matched && !child.fragment_id.is_empty() {
                context.writer.write("<webhub-route")?;
                if !child.path.is_empty() {
                    context.writer.write(" path=\"")?;
                    context.writer.write(&child.path)?;
                    context.writer.write("\"")?;
                }
                context.writer.write(" component=\"")?;
                context.writer.write(&child.fragment_id)?;
                context.writer.write("\"")?;
                if child.exact {
                    context.writer.write(" exact")?;
                }
                route_renderer::write_route_pending_attrs(context.writer, child)?;
                context
                    .writer
                    .write(" style=\"display:none\"></webhub-route>")?;
            }
        }

        Ok(())
    }

    /// Emit a `<script type="importmap">` tag that registers a component's
    /// CSS module under its specifier via a `data:text/css,…` URI.
    ///
    /// Requires Multiple Import Maps (Chrome 133+); each call emits an
    /// independent importmap that the browser merges at the document
    /// level. The per-render CSP nonce is applied when set (importmap
    /// scripts honor `script-src`).
    ///
    /// Example for `my-comp` with CSS `span{color:blue;}`:
    /// `<script type="importmap" nonce="...">{"imports":{"my-comp":"data:text/css,span{color:blue;}"}}</script>`
    fn emit_css_module_importmap(
        &self,
        specifier: &str,
        css: &str,
        context: &mut webhubProcessContext,
    ) -> Result<()> {
        let tag = crate::css_module::build_importmap_tag(specifier, css, context.nonce);
        context.writer.write(&tag)?;
        Ok(())
    }

    /// Emit a component's CSS module importmap on its first render
    /// (deduped by `rendered_components`) into the component's light DOM,
    /// so the browser registers it under the component's specifier
    /// before the shadow root template is parsed. See
    /// [`Self::emit_css_module_importmap`] for the emitted shape.
    ///
    /// Only components rendered on the current route get inline
    /// definitions; others receive theirs via `templateStyles` during
    /// SPA partial navigation.
    fn emit_css_module(
        &self,
        component: &webhub_protocol::webhubFragmentComponent,
        context: &mut webhubProcessContext,
    ) -> Result<()> {
        if !context.rendered_components.contains(&component.fragment_id) {
            if let Some(css) = context
                .protocol
                .components
                .get(&component.fragment_id)
                .map(|c| c.css.as_str())
                .filter(|s| !s.is_empty())
            {
                self.emit_css_module_importmap(&component.fragment_id, css, context)?;
            }
        }
        Ok(())
    }

    /// Process a route fragment — renders `<webhub-route>` with matched/hidden state.
    fn process_route(
        &self,
        route_frag: &webhub_protocol::webhubFragmentRoute,
        best_route: &Option<(String, route_matcher::RouteMatch)>,
        context: &mut webhubProcessContext,
    ) -> Result<()> {
        let is_matched = best_route
            .as_ref()
            .is_some_and(|(best_key, _)| *best_key == route_frag.fragment_id);

        context.writer.write("<webhub-route")?;
        if !route_frag.path.is_empty() {
            context.writer.write(" path=\"")?;
            context.writer.write(&route_frag.path)?;
            context.writer.write("\"")?;
        }
        if !route_frag.fragment_id.is_empty() {
            context.writer.write(" component=\"")?;
            context.writer.write(&route_frag.fragment_id)?;
            context.writer.write("\"")?;
        }
        if route_frag.exact {
            context.writer.write(" exact")?;
        }
        route_renderer::write_route_pending_attrs(context.writer, route_frag)?;

        if is_matched {
            // Emit data-ri for O(1) client-side element binding
            let ri = context.route_chain_index;
            context.route_chain_index += 1;
            context.writer.write(" data-ri=\"")?;
            write_usize(context.writer, ri)?;
            context.writer.write("\" active>")?;

            if !route_frag.fragment_id.is_empty() {
                let saved_route_base = context.route_base.clone();
                let saved_route_children = std::mem::take(&mut context.route_children);
                if let Some((_, ref rm)) = best_route {
                    context.route_base = Cow::Owned(route_matcher::compute_route_base(
                        context.request_path,
                        rm.consumed_segments,
                    ));
                }

                context.route_children = route_frag.children.clone();

                let comp = webhub_protocol::webhubFragmentComponent {
                    fragment_id: route_frag.fragment_id.clone(),
                };

                context.writer.write("<")?;
                context.writer.write(&route_frag.fragment_id)?;
                if let Some(p) = &context.plugin {
                    p.write_route_component_state(context.state, context.writer)?;
                }
                context.writer.write(">")?;

                self.process_component(&comp, context)?;

                context.writer.write("</")?;
                context.writer.write(&route_frag.fragment_id)?;
                context.writer.write(">")?;

                context.route_base = saved_route_base;
                context.route_children = saved_route_children;
            }
        } else {
            context.writer.write(" style=\"display:none\">")?;
        }

        context.writer.write("</webhub-route>")?;
        Ok(())
    }

    /// Process a component fragment.
    fn process_component(
        &self,
        component: &webhub_protocol::webhubFragmentComponent,
        context: &mut webhubProcessContext,
    ) -> Result<()> {
        // Emit the component's CSS module importmap into its light DOM
        // on first encounter (see `emit_css_module`).
        if !context.rendered_components.contains(&component.fragment_id) {
            self.emit_css_module(component, context)?;
        }

        // Track this component as rendered (for selective f-template emission)
        context
            .rendered_components
            .insert(component.fragment_id.clone());

        // Save parent scope
        let saved_local_vars = std::mem::take(&mut context.local_vars);
        let saved_component_attrs = std::mem::take(&mut context.component_attrs);

        // Component gets accumulated attrs as its local vars.
        context.local_vars = saved_component_attrs;

        if let Some(p) = &mut context.plugin {
            p.push_scope();
        }

        self.process_fragment_id(&component.fragment_id, context)?;

        if let Some(p) = &mut context.plugin {
            p.pop_scope();
        }

        // Restore parent scope
        context.local_vars = saved_local_vars;
        context.component_attrs = HashMap::new();

        Ok(())
    }

    /// Resolve a dotted path value, checking local variables first, then global state.
    fn resolve_value(&self, path: &str, context: &webhubProcessContext<'_>) -> Option<Value> {
        resolve_value_from_sources(path, &context.local_vars, context.state).map(Cow::into_owned)
    }

    /// Evaluate a condition expression against the current context.
    ///
    /// Uses a resolver closure that checks local variables first, then falls
    /// back to global state — avoiding a full clone of the state tree.
    /// Returns false if the condition references a missing value.
    fn evaluate_condition(
        &self,
        condition: &webhub_protocol::ConditionExpr,
        context: &webhubProcessContext,
    ) -> Result<bool> {
        let local_vars = &context.local_vars;
        let state = context.state;
        match evaluate_with_resolver(condition, |path| {
            resolve_value_from_sources(path, local_vars, state)
        }) {
            Ok(result) => Ok(result),
            Err(ExpressionError::MissingValue(_)) => Ok(false),
            Err(e) => Err(HandlerError::Evaluation(e.to_string())),
        }
    }

    /// Process a for loop fragment.
    ///
    /// Creates a new context for each iteration that includes the current loop item.
    /// This allows nested templates to access both the loop variable and any parent context.
    /// Example: `for item in items` makes "item" available in the loop body.
    fn process_for_loop(
        &self,
        for_loop: &webhub_protocol::webhubFragmentFor,
        context: &mut webhubProcessContext,
    ) -> Result<()> {
        let collection_name = &for_loop.collection;

        // If the collection is missing, treat it as empty (0 iterations) — matches NodeJS behavior.
        // Hydration comments are always emitted regardless of collection presence.
        let items = match self.resolve_value(collection_name, context) {
            Some(Value::Array(arr)) => arr,
            Some(_) => {
                return Err(HandlerError::TypeError(format!(
                    "Collection '{}' is not an array",
                    collection_name
                )))
            }
            None => Vec::new(),
        };

        if let Some(p) = &mut context.plugin {
            p.on_for_start(&for_loop.fragment_id, context.writer)?;
        }

        // Hot-loop optimisation: the loop variable name is `String`-keyed
        // in `local_vars`. The naive impl re-inserts (and so re-allocates
        // the key) on every iteration — a 1000-item loop pays 2000 String
        // clones for the key alone. Instead, we save the outer-scope
        // value (if any) ONCE before the loop, install the key ONCE with
        // an empty placeholder, then overwrite the value in-place each
        // iteration via `get_mut`. Restoration at the end happens once.
        let item_name = for_loop.item.as_str();
        let saved_value = context.local_vars.remove(item_name);
        // Pre-insert the key so per-iteration `get_mut` is infallible.
        // Cost: at most one `String::from(item_name)` for the lifetime
        // of the loop, regardless of iteration count.
        if !items.is_empty() {
            context
                .local_vars
                .insert(item_name.to_string(), Value::Null);
        }
        for (i, item) in items.into_iter().enumerate() {
            if let Some(p) = &mut context.plugin {
                p.on_repeat_item_start(i, context.writer)?;
                p.push_scope();
            }

            // O(1) value swap; no key allocation.
            if let Some(slot) = context.local_vars.get_mut(item_name) {
                *slot = item;
            }
            self.process_fragment_id(&for_loop.fragment_id, context)?;

            if let Some(p) = &mut context.plugin {
                p.pop_scope();
                p.on_repeat_item_end(i, context.writer)?;
            }
        }
        // Restore outer scope (or remove the placeholder we installed).
        match saved_value {
            Some(value) => {
                context.local_vars.insert(item_name.to_string(), value);
            }
            None => {
                context.local_vars.remove(item_name);
            }
        }

        if let Some(p) = &mut context.plugin {
            p.on_for_end(&for_loop.fragment_id, context.writer)?;
        }

        Ok(())
    }

    /// Process a signal fragment.
    ///
    /// Looks up the value in the context first (for local variables), then in the global state.
    /// This prioritization allows local variables (like loop items) to override global state.
    /// If the value is not found in either scope, an empty string is returned.
    fn process_signal(
        &self,
        signal: &webhub_protocol::webhubFragmentSignal,
        context: &mut webhubProcessContext,
    ) -> Result<()> {
        // Hook: emit nonce meta and CSS <link> tags before </head>.
        // Guarded by `head_end_emitted` so a malformed protocol cannot
        // emit nonce/preloads/inject more than once per render.
        if signal.raw && signal.value == "head_end" && !context.head_end_emitted {
            context.head_end_emitted = true;
            if let Some(nonce) = context.nonce {
                context
                    .writer
                    .write("<meta name=\"webhub-nonce\" content=\"")?;
                context
                    .writer
                    .write(&crate::html_encode::encode_safe(nonce))?;
                context.writer.write("\">")?;
            }

            // Emit CSS <link> tags in <head> for Link-strategy components.
            // For components with a non-empty css_href:
            //   Link + Shadow → <link rel="preload"> (stylesheet is in shadow root)
            //   Link + Light  → <link rel="stylesheet"> (no shadow root)
            //
            // Style and Module strategies emit their CSS during component
            // rendering (shadow-DOM template / importmap respectively).
            let is_link = context.protocol.css_strategy() == webhub_protocol::CssStrategy::Link;
            let is_shadow = context.protocol.dom_strategy() == webhub_protocol::DomStrategy::Shadow;

            if is_link {
                let (needed_components, _) =
                    crate::route_handler::get_needed_components_for_request(
                        context.protocol,
                        context.entry_id,
                        context.request_path,
                        "",
                        (context.component_index, context.route_index),
                    )?;

                for name in &needed_components {
                    if let Some(href) = context
                        .protocol
                        .components
                        .get(name)
                        .map(|c| c.css_href.as_str())
                        .filter(|h| !h.is_empty())
                    {
                        if is_shadow {
                            context.writer.write("<link rel=\"preload\" href=\"")?;
                            context.writer.write(href)?;
                            context
                                .writer
                                .write("\" as=\"style\" data-webhub-ssr-preload=\"style\">")?;
                        } else {
                            context.writer.write("<link rel=\"stylesheet\" href=\"")?;
                            context.writer.write(href)?;
                            context.writer.write("\">")?;
                        }
                    }
                }
            }

            // Per-render `head_inject` HTML — image preloads, A/B test
            // markers, etc. supplied by the host via RenderOptions.
            // Emitted at the structural head_end boundary, after the
            // built-in nonce + CSS-link emissions, so host injects
            // appear immediately before `</head>`.
            if let Some(html) = context.head_inject {
                context.writer.write(html)?;
            }
        }

        // Hook: emit component templates and host body_inject before </body>.
        // Single guarded block so the dedup flag protects both the
        // hydration emission and the host inject from a malformed
        // protocol that fires `body_end` more than once per render.
        if signal.raw && signal.value == "body_end" && !context.body_end_emitted {
            context.body_end_emitted = true;
            if context.plugin.is_some() {
                // Emit templates for all REACHABLE components on the current route,
                // not just those rendered in this SSR pass. Components inside false
                // <if> blocks or empty <for> loops are reachable via client-side
                // state changes and need their templates available without a server
                // round-trip. The graph walker follows conditional and loop branches
                // unconditionally, but only descends into the matched route chain —
                // components on other routes are delivered via SPA partial navigation.
                let reachable = crate::route_handler::collect_reachable_components_for_request(
                    context.protocol,
                    context.entry_id,
                    context.request_path,
                    context.route_index,
                );
                let state_selection =
                    collect_hydration_state(context.protocol, reachable.iter().map(String::as_str));

                // Emit CSS module importmaps for reachable-but-unrendered
                // components so the framework can adopt them when an `<if>`
                // condition flips true client-side.
                for name in &reachable {
                    if !context.rendered_components.contains(name) {
                        if let Some(css) = context
                            .protocol
                            .components
                            .get(name)
                            .map(|c| c.css.as_str())
                            .filter(|s| !s.is_empty())
                        {
                            self.emit_css_module_importmap(name, css, context)?;
                        }
                    }
                }

                // Try to collect split webhub template payloads. If the plugin
                // returns None (non-webhub templates, e.g. FAST), fall back to
                // separate emission.
                let template_payloads = context
                    .plugin
                    .as_ref()
                    .and_then(|p| p.collect_template_payloads(context.protocol, &reachable));

                if template_payloads.is_none() {
                    // Non-JS templates (FAST plugins) - emit separately
                    if let Some(ref p) = context.plugin {
                        p.emit_templates(
                            context.protocol,
                            &reachable,
                            context.nonce,
                            context.writer,
                        )?;
                    }
                }

                // Compute the inventory hex from actually rendered components.
                let inventory_hex = crate::route_handler::encode_component_inventory(
                    &context.rendered_components,
                    context.component_index,
                );

                // Chain
                let chain = crate::route_handler::collect_route_chain(
                    context.protocol,
                    context.entry_id,
                    context.request_path,
                    context.route_index,
                );
                let chain_json: Vec<Value> = chain
                    .iter()
                    .map(crate::route_handler::RouteChainEntry::to_json)
                    .collect();

                // CSS hrefs emitted during SSR (Link-strategy components)
                let is_link = context.protocol.css_strategy() == webhub_protocol::CssStrategy::Link;
                let mut css_hrefs: Vec<&str> = Vec::new();
                if is_link {
                    for name in &reachable {
                        if let Some(href) = context
                            .protocol
                            .components
                            .get(name)
                            .map(|c| c.css_href.as_str())
                            .filter(|h| !h.is_empty())
                        {
                            css_hrefs.push(href);
                        }
                    }
                }

                // Module style specifiers emitted during SSR
                let mut style_specs: Vec<&str> = Vec::new();
                for name in &reachable {
                    if context
                        .protocol
                        .components
                        .get(name)
                        .map(|c| !c.css.is_empty())
                        .unwrap_or(false)
                    {
                        style_specs.push(name);
                    }
                }

                let empty_payloads: [webhubTemplatePayload<'_>; 0] = [];
                let payloads = template_payloads.as_deref().unwrap_or(&empty_payloads);
                write_webhub_data_block(
                    context.writer,
                    webhubBootstrap {
                        state: context.state,
                        state_selection,
                        chain: &chain_json,
                        inventory: &inventory_hex,
                        nonce: context.nonce,
                        css_hrefs: &css_hrefs,
                        style_specs: &style_specs,
                        templates: payloads,
                    },
                )?;

                // Let the active plugin emit any framework-specific executable
                // side channel. FAST plugins default to no-op; webhub installs
                // templateFns. Client packages parse #webhub-data lazily.
                if let Some(ref plugin) = context.plugin {
                    plugin.emit_bootstrap_extension(
                        BootstrapExtensionContext {
                            protocol: context.protocol,
                            components: &reachable,
                            payloads,
                            nonce: context.nonce,
                        },
                        context.writer,
                    )?;
                }
            }

            // Per-render `body_inject` HTML — dev livereload script,
            // analytics, etc. supplied by the host via RenderOptions.
            // Inside the dedup block but outside the plugin-only
            // sub-block above, so it fires regardless of whether a
            // hydration plugin is active. Appears immediately before
            // `</body>`.
            if let Some(html) = context.body_inject {
                context.writer.write(html)?;
            }
        }

        if let Some(p) = &mut context.plugin {
            p.on_binding_start(&signal.value, context.writer)?;
        }

        if let Some(value) = self.resolve_value(&signal.value, context) {
            self.write_signal_value(&value, signal.raw, context.writer)?;
        }

        if let Some(p) = &mut context.plugin {
            p.on_binding_end(&signal.value, context.writer)?;
        }
        Ok(())
    }

    /// Write a signal value directly to the writer, avoiding intermediate String allocation.
    /// For HTML-escaped output, writes the Cow from `encode_safe` directly.
    fn write_signal_value(
        &self,
        value: &Value,
        raw: bool,
        writer: &mut dyn ResponseWriter,
    ) -> Result<()> {
        if raw {
            match value {
                Value::String(s) => writer.write(s),
                _ => writer.write(&value.to_string()),
            }
        } else {
            match value {
                Value::String(s) => writer.write(&crate::html_encode::encode_safe(s)),
                _ => {
                    let s = value.to_string();
                    writer.write(&crate::html_encode::encode_safe(&s))
                }
            }
        }
    }

    /// Process an if condition fragment.
    fn process_if(
        &self,
        if_cond: &webhub_protocol::webhubFragmentIf,
        context: &mut webhubProcessContext,
    ) -> Result<()> {
        let condition = if_cond
            .condition
            .as_ref()
            .ok_or_else(|| HandlerError::Rendering("If fragment missing condition".to_string()))?;
        let condition_met = self.evaluate_condition(condition, context)?;

        if let Some(p) = &mut context.plugin {
            p.on_if_start(&if_cond.fragment_id, context.writer)?;
        }

        if condition_met {
            if let Some(p) = &mut context.plugin {
                p.push_scope();
            }

            self.process_fragment_id(&if_cond.fragment_id, context)?;

            if let Some(p) = &mut context.plugin {
                p.pop_scope();
            }
        }

        if let Some(p) = &mut context.plugin {
            p.on_if_end(&if_cond.fragment_id, context.writer)?;
        }

        Ok(())
    }

    /// Process an attribute fragment by rendering the attribute name/value pair.
    fn process_attribute(
        &self,
        attr: &webhub_protocol::webhubFragmentAttribute,
        context: &mut webhubProcessContext,
    ) -> Result<()> {
        // Initialize component attribute accumulator on attrStart
        if attr.attr_start {
            context.component_attrs = HashMap::new();
        }

        // Boolean attribute with condition tree
        if let Some(condition) = &attr.condition_tree {
            let condition_met = self.evaluate_condition(condition, context)?;

            if !attr.attr_skip {
                let name = component_attr_name(&attr.name);
                context
                    .component_attrs
                    .insert(name, Value::Bool(condition_met));
            }

            if condition_met {
                context.writer.write(" ")?;
                context.writer.write(&attr.name)?;
            }
            return Ok(());
        }

        // Template attribute (mixed static + dynamic)
        if !attr.template.is_empty() {
            let raw_value = self.render_template_attr_value(&attr.template, context)?;
            let escaped = crate::html_encode::encode_safe(&raw_value);
            write_attr(context.writer, &attr.name, &escaped)?;

            if !attr.attr_skip {
                let name = component_attr_name(&attr.name);
                context
                    .component_attrs
                    .insert(name, Value::String(raw_value));
            }
            return Ok(());
        }

        // Simple attribute
        if !attr.value.is_empty() {
            if attr.raw_value {
                // Static attribute — value is the literal string
                write_attr(context.writer, &attr.name, &attr.value)?;
                if !attr.attr_skip {
                    let name = component_attr_name(&attr.name);
                    context
                        .component_attrs
                        .insert(name, Value::String(attr.value.clone()));
                }
            } else if attr.complex {
                // Complex attribute — resolve value, don't render to HTML, store as state
                if let Some(value) = self.resolve_value(&attr.value, context) {
                    if !attr.attr_skip {
                        let stripped = attr.name.strip_prefix(':').unwrap_or(&attr.name);
                        let name = component_attr_name(stripped);
                        context.component_attrs.insert(name, value);
                    }
                }
            } else {
                // Dynamic attribute — resolve and render
                let value = self.resolve_value(&attr.value, context);
                // Always emit the attribute so FAST hydration markers
                // (`data-fe`) match the DOM node structure.
                match &value {
                    Some(Value::String(s)) => {
                        write_attr(
                            context.writer,
                            &attr.name,
                            &crate::html_encode::encode_safe(s),
                        )?;
                    }
                    Some(Value::Null) | None => {
                        write_attr(context.writer, &attr.name, "")?;
                    }
                    Some(other) => {
                        let s = other.to_string();
                        write_attr(
                            context.writer,
                            &attr.name,
                            &crate::html_encode::encode_safe(&s),
                        )?;
                    }
                }

                if !attr.attr_skip {
                    let name = component_attr_name(&attr.name);
                    context
                        .component_attrs
                        .insert(name, value.unwrap_or(Value::String(String::new())));
                }
            }
        }

        Ok(())
    }

    /// Render a template attribute's fragments into a raw (unescaped) string.
    fn render_template_attr_value(
        &self,
        template_id: &str,
        context: &webhubProcessContext,
    ) -> Result<String> {
        let fragments = context
            .protocol
            .fragments
            .get(template_id)
            .ok_or_else(|| HandlerError::MissingFragment(template_id.to_string()))?;
        let mut raw_value = String::new();
        for frag in &fragments.fragments {
            match frag.fragment.as_ref() {
                Some(Fragment::Raw(raw)) => raw_value.push_str(&raw.value),
                Some(Fragment::Signal(signal)) => {
                    if let Some(value) = self.resolve_value(&signal.value, context) {
                        match &value {
                            Value::String(s) => raw_value.push_str(s),
                            _ => raw_value.push_str(&value.to_string()),
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(raw_value)
    }

    /// Render the UI based on the protocol and state.
    pub fn render<'a>(
        &self,
        protocol: &'a Protocol,
        state: &'a Value,
        options: &RenderOptions<'a>,
        writer: &'a mut dyn ResponseWriter,
    ) -> Result<()> {
        let document = protocol.protocol();
        if !document.fragments.contains_key(options.entry_id) {
            return Err(HandlerError::MissingFragment(options.entry_id.to_string()));
        }
        let mut context = webhubProcessContext {
            protocol: document,
            state,
            writer,
            local_vars: HashMap::new(),
            component_attrs: HashMap::new(),
            request_path: options.request_path,
            route_base: Cow::Borrowed("/"),
            rendered_components: HashSet::new(),
            plugin: self.plugin_factory.map(|f| f()),
            route_children: Vec::new(),
            entry_id: options.entry_id,
            // Same defensive normalisation as `handle()`. See the
            // doc-comment there for the CSP-outage rationale.
            nonce: options.nonce.filter(|s| !s.is_empty()),
            head_inject: options.head_inject.filter(|s| !s.is_empty()),
            body_inject: options.body_inject.filter(|s| !s.is_empty()),
            head_end_emitted: false,
            component_index: protocol.component_index(),
            body_end_emitted: false,
            route_index: protocol.route_index(),
            route_chain_index: 0,
        };

        self.process_fragment_id(options.entry_id, &mut context)?;
        writer.end()?;

        Ok(())
    }
}

impl Default for webhubHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Write ` name="value"` to the writer without allocating a format string.
fn write_attr(writer: &mut dyn ResponseWriter, name: &str, value: &str) -> Result<()> {
    writer.write(" ")?;
    writer.write(name)?;
    writer.write("=\"")?;
    writer.write(value)?;
    writer.write("\"")
}

#[cfg(test)]
fn handle(
    protocol: &webhubProtocol,
    state: &Value,
    options: &RenderOptions<'_>,
    writer: &mut dyn ResponseWriter,
) -> Result<()> {
    let handler = webhubHandler::new();
    handler.handle(protocol, state, options, writer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use webhub_protocol::{
        web_ui_fragment, ComparisonOperator, ConditionExpr, FragmentList, LogicalOperator,
        webhubFragmentAttribute,
    };
    use webhub_test_utils::test_json;

    // A simple test writer implementation
    struct TestWriter {
        content: RefCell<String>,
        ended: RefCell<bool>,
    }

    impl TestWriter {
        fn new() -> Self {
            Self {
                content: RefCell::new(String::new()),
                ended: RefCell::new(false),
            }
        }

        fn get_content(&self) -> String {
            self.content.borrow().clone()
        }

        fn is_ended(&self) -> bool {
            *self.ended.borrow()
        }
    }

    impl ResponseWriter for TestWriter {
        fn write(&mut self, content: &str) -> Result<()> {
            self.content.borrow_mut().push_str(content);
            Ok(())
        }

        fn end(&mut self) -> Result<()> {
            *self.ended.borrow_mut() = true;
            Ok(())
        }
    }

    #[test]
    fn test_handle_raw() {
        // Create a simple protocol
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("Hello, webhub!")],
            },
        );

        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});

        // Create a test writer
        let mut writer = TestWriter::new();

        // Handle the protocol
        assert!(
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer
            )
            .is_ok(),
            "Failed to handle raw protocol"
        );

        // Check the output
        assert_eq!(writer.get_content(), "Hello, webhub!");
        assert!(writer.is_ended());
    }

    #[test]
    fn test_handle_signal() {
        // Create a protocol with a signal
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("Hello, "),
                    webhubFragment::signal("name", false),
                    webhubFragment::raw("!"),
                ],
            },
        );

        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"name": "webhub"});

        // Create a test writer
        let mut writer = TestWriter::new();

        // Handle the protocol
        assert!(
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer
            )
            .is_ok(),
            "Failed to handle signal protocol"
        );

        // Check the output
        assert_eq!(writer.get_content(), "Hello, webhub!");
        assert!(writer.is_ended());
    }

    #[test]
    fn test_handle_for_loop() {
        // Create a protocol with a for loop
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("People: "),
                    webhubFragment::for_loop("person", "people", "person-item"),
                ],
            },
        );

        fragments.insert(
            "person-item".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::signal("person.name", false),
                    webhubFragment::raw(", "),
                ],
            },
        );

        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "people": [
                {"name": "Alice"},
                {"name": "Bob"},
                {"name": "Charlie"}
            ]
        });

        // Create a test writer
        let mut writer = TestWriter::new();

        // Handle the protocol
        assert!(
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer
            )
            .is_ok(),
            "Failed to handle for loop protocol"
        );

        // Check the output
        assert_eq!(writer.get_content(), "People: Alice, Bob, Charlie, ");
        assert!(writer.is_ended());
    }

    #[test]
    fn test_handle_if_condition() {
        // Create a protocol with an if condition
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("Status: "),
                    webhubFragment::if_cond(
                        webhub_protocol::ConditionExpr::identifier("isActive"),
                        "active-content",
                    ),
                    webhubFragment::raw("End"),
                ],
            },
        );

        fragments.insert(
            "active-content".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("Active")],
            },
        );

        let protocol = webhubProtocol::new(fragments);

        // Test with isActive = true
        let state_true = test_json!({"isActive": true});
        let mut writer_true = TestWriter::new();
        assert!(
            handle(
                &protocol,
                &state_true,
                &RenderOptions::new("index.html", "/"),
                &mut writer_true
            )
            .is_ok(),
            "Failed to handle if condition (true case)"
        );
        assert_eq!(writer_true.get_content(), "Status: ActiveEnd");
        assert!(writer_true.is_ended());

        // Test with isActive = false
        let state_false = test_json!({"isActive": false});
        let mut writer_false = TestWriter::new();
        assert!(
            handle(
                &protocol,
                &state_false,
                &RenderOptions::new("index.html", "/"),
                &mut writer_false
            )
            .is_ok(),
            "Failed to handle if condition (false case)"
        );
        assert_eq!(writer_false.get_content(), "Status: End");
        assert!(writer_false.is_ended());
    }

    #[test]
    fn test_handle_component() {
        // Create a protocol with a component
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("Component: "),
                    webhubFragment::component("my-component"),
                ],
            },
        );

        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>Component Content</div>")],
            },
        );

        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});

        // Create a test writer
        let mut writer = TestWriter::new();

        // Handle the protocol
        assert!(
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer
            )
            .is_ok(),
            "Failed to handle component protocol"
        );

        // Check the output
        assert_eq!(
            writer.get_content(),
            "Component: <div>Component Content</div>"
        );
        assert!(writer.is_ended());
    }

    #[test]
    fn test_missing_fragment() {
        // Create a protocol with a missing fragment reference
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::component("missing-component")],
            },
        );

        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});

        // Create a test writer
        let mut writer = TestWriter::new();

        // Handle the protocol
        let result = handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        );

        // Expect an error
        assert!(result.is_err());
        if let Err(HandlerError::MissingFragment(fragment_id)) = result {
            assert_eq!(fragment_id, "missing-component");
        } else {
            panic!("Expected MissingFragment error");
        }
    }

    #[test]
    fn test_missing_signal_renders_empty() {
        // A signal referencing a field absent from state should render as empty
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("Hello, "),
                    webhubFragment::signal("missing_field", false),
                    webhubFragment::raw("!"),
                ],
            },
        );

        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});

        let mut writer = TestWriter::new();

        assert!(
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer
            )
            .is_ok(),
            "Missing signal should not produce an error"
        );

        assert_eq!(writer.get_content(), "Hello, !");
        assert!(writer.is_ended());
    }

    // ── Boolean attribute rendering tests ─────────────────────────────

    #[test]
    fn test_boolean_attr_true() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<button"),
                    webhubFragment::attribute_boolean(
                        "disabled",
                        ConditionExpr::identifier("isDisabled"),
                    ),
                    webhubFragment::raw(">Click</button>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"isDisabled": true});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "<button disabled>Click</button>");
    }

    #[test]
    fn test_boolean_attr_false() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<button"),
                    webhubFragment::attribute_boolean(
                        "disabled",
                        ConditionExpr::identifier("isDisabled"),
                    ),
                    webhubFragment::raw(">Click</button>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"isDisabled": false});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "<button>Click</button>");
    }

    #[test]
    fn test_boolean_attr_missing() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<input type=\"checkbox\""),
                    webhubFragment::attribute_boolean(
                        "checked",
                        ConditionExpr::identifier("checked"),
                    ),
                    webhubFragment::raw(">"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "<input type=\"checkbox\">");
    }

    #[test]
    fn test_boolean_attr_multiple() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<input type=\"checkbox\""),
                    webhubFragment::attribute_boolean(
                        "checked",
                        ConditionExpr::identifier("checked"),
                    ),
                    webhubFragment::attribute_boolean(
                        "disabled",
                        ConditionExpr::identifier("disabled"),
                    ),
                    webhubFragment::raw(">"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"checked": true, "disabled": false});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "<input type=\"checkbox\" checked>");
    }

    // ── Simple attribute rendering tests ──────────────────────────────

    #[test]
    fn test_attribute_with_value() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<input"),
                    webhubFragment::attribute("value", "inputValue"),
                    webhubFragment::raw(">"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"inputValue": "Hello"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "<input value=\"Hello\">");
    }

    #[test]
    fn test_attribute_with_falsy_numeric() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div name=\"test\""),
                    webhubFragment::attribute("handle", "number"),
                    webhubFragment::raw("></div>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"number": 0});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div name=\"test\" handle=\"0\"></div>"
        );
    }

    // ── Dynamic attribute escaping for non-string JSON types ─────────

    #[test]
    fn test_attribute_array_value_is_escaped() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<a"),
                    webhubFragment::attribute("href", "value"),
                    webhubFragment::raw(">demo</a>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"value": ["\" autofocus onfocus=alert(1) x=\""]});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        let content = writer.get_content();
        // All inner double quotes must be entity-escaped so that the
        // browser never sees a second attribute boundary.
        assert!(
            content.contains("&quot;"),
            "Double quotes inside attribute value must be escaped: {content}"
        );
        // The href attribute value must be a single contiguous quoted
        // string — no extra attributes should appear.
        assert_eq!(
            content.matches("=\"").count(),
            1,
            "Only one attribute assignment expected: {content}"
        );
    }

    #[test]
    fn test_attribute_object_value_is_escaped() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div"),
                    webhubFragment::attribute("data-cfg", "cfg"),
                    webhubFragment::raw("></div>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"cfg": {"key": "\" onfocus=alert(1) x=\""}});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        let content = writer.get_content();
        assert!(
            content.contains("&quot;"),
            "Double quotes inside attribute value must be escaped: {content}"
        );
        assert_eq!(
            content.matches("=\"").count(),
            1,
            "Only one attribute assignment expected: {content}"
        );
    }

    // ── Template attribute rendering tests ────────────────────────────

    #[test]
    fn test_mixed_attribute_template() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<input"),
                    webhubFragment::attribute_template("value", "attr-1"),
                    webhubFragment::raw(">"),
                ],
            },
        );
        fragments.insert(
            "attr-1".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("hello "),
                    webhubFragment::signal("item", false),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"item": "world"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "<input value=\"hello world\">");
    }

    // ── Raw signal rendering test ─────────────────────────────────────

    #[test]
    fn test_raw_signal_not_escaped() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::signal("html", false),
                    webhubFragment::signal("html", true),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"html": "<strong>hi</strong>"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "&lt;strong&gt;hi&lt;&#x2F;strong&gt;<strong>hi</strong>"
        );
    }

    // ── Nested for loop tests ─────────────────────────────────────────

    #[test]
    fn test_nested_for_loop() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("outerItem", "outerItems", "outer"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "outer".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("innerItem", "outerItem.innerItems", "inner"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "inner".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<span>Inner</span>")],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "outerItems": [
                {"innerItems": [{"name": "A"}, {"name": "B"}]},
                {"innerItems": [{"name": "C"}]}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><div><span>Inner</span><span>Inner</span></div><div><span>Inner</span></div></div>"
        );
    }

    #[test]
    fn test_nested_for_with_signals() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("outerItem", "outerItems", "outerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "outerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("innerItem", "outerItem.innerItems", "innerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "innerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("innerItem.name", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "outerItems": [
                {"innerItems": [{"name": "Item1"}, {"name": "Item2"}]},
                {"innerItems": [{"name": "Item3"}, {"name": "Item4"}]}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><div><span>Item1</span><span>Item2</span></div><div><span>Item3</span><span>Item4</span></div></div>"
        );
    }

    #[test]
    fn test_nested_for_with_global_state() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("outerItem", "outerItems", "outerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "outerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::signal("globalOuter", false),
                    webhubFragment::for_loop("innerItem", "outerItem.innerItems", "innerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "innerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("innerItem.name", false),
                    webhubFragment::signal("globalInner", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "globalOuter": "GO",
            "globalInner": "GI",
            "outerItems": [
                {"innerItems": [{"name": "Item1"}, {"name": "Item2"}]},
                {"innerItems": [{"name": "Item3"}, {"name": "Item4"}]}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><div>GO<span>Item1GI</span><span>Item2GI</span></div><div>GO<span>Item3GI</span><span>Item4GI</span></div></div>"
        );
    }

    // ── For + If state scoping tests ──────────────────────────────────

    #[test]
    fn test_if_in_for_uses_local_state() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::for_loop("item", "items", "item-tpl")],
            },
        );
        fragments.insert(
            "item-tpl".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::if_cond(
                    ConditionExpr::identifier("item.visible"),
                    "visible-tpl",
                )],
            },
        );
        fragments.insert(
            "visible-tpl".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::signal("item.name", false)],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"items": [{"name": "Show", "visible": true}, {"name": "Hide", "visible": false}]});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "Show");
    }

    #[test]
    fn test_for_if_local_overrides_global() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::for_loop("item", "items", "item-tpl")],
            },
        );
        fragments.insert(
            "item-tpl".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::if_cond(
                    ConditionExpr::identifier("item.flag"),
                    "show-tpl",
                )],
            },
        );
        fragments.insert(
            "show-tpl".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("yes")],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        // Global flag is true, but local item.flag is false for second item
        let state = test_json!({"flag": true, "items": [{"flag": true}, {"flag": false}]});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "yes");
    }

    // ── Component attribute state tests ───────────────────────────────

    #[test]
    fn test_component_attr_state_simple() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-comp"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                value: "Attribute Title".into(),
                                attr_start: true,
                                raw_value: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-comp"),
                    webhubFragment::raw("</my-comp>"),
                ],
            },
        );
        fragments.insert(
            "my-comp".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"title": "Global Title"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-comp title=\"Attribute Title\"><span>Attribute Title</span></my-comp>"
        );
    }

    #[test]
    fn test_component_attr_state_template() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-comp"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                template: "title-attr".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-comp"),
                    webhubFragment::raw("</my-comp>"),
                ],
            },
        );
        fragments.insert(
            "title-attr".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("hello "),
                    webhubFragment::signal("item", false),
                ],
            },
        );
        fragments.insert(
            "my-comp".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"item": "<world>"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-comp title=\"hello &lt;world&gt;\"><span>hello &lt;world&gt;</span></my-comp>"
        );
    }

    #[test]
    fn test_component_attr_camel_case() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-comp"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "data-title".into(),
                                template: "dt-attr".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-comp"),
                    webhubFragment::raw("</my-comp>"),
                ],
            },
        );
        fragments.insert(
            "dt-attr".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("prefix "),
                    webhubFragment::signal("item", false),
                ],
            },
        );
        fragments.insert(
            "my-comp".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("dataTitle", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"item": "a&b"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-comp data-title=\"prefix a&amp;b\"><span>prefix a&amp;b</span></my-comp>"
        );
    }

    #[test]
    fn test_component_complex_attr() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-comp"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: ":item".into(),
                                value: "complexItem".into(),
                                attr_start: true,
                                complex: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-comp"),
                    webhubFragment::raw("</my-comp>"),
                ],
            },
        );
        fragments.insert(
            "my-comp".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("item.foo", false),
                    webhubFragment::raw("</span><p>"),
                    webhubFragment::signal("item.bar", false),
                    webhubFragment::raw("</p>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"complexItem": {"foo": 1, "bar": "true"}});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-comp><span>1</span><p>true</p></my-comp>"
        );
    }

    #[test]
    fn test_component_no_parent_pollution() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<parent"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "var".into(),
                                value: "var".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("parent"),
                    webhubFragment::raw("</parent>"),
                ],
            },
        );
        fragments.insert(
            "parent".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("Before: "),
                    webhubFragment::signal("var", false),
                    webhubFragment::raw("<child foo"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "var".into(),
                                value: "replaced".into(),
                                raw_value: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("child"),
                    webhubFragment::raw("Label</child>After: "),
                    webhubFragment::signal("var", false),
                ],
            },
        );
        fragments.insert("child".to_string(), FragmentList { fragments: vec![] });
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"var": "original"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<parent var=\"original\">Before: original<child foo var=\"replaced\">Label</child>After: original</parent>"
        );
    }

    #[test]
    fn test_component_boolean_attr_state() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-comp"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "disabled".into(),
                                attr_start: true,
                                condition_tree: Some(ConditionExpr::identifier("isDisabled")),
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-comp"),
                    webhubFragment::raw("</my-comp>"),
                ],
            },
        );
        fragments.insert(
            "my-comp".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::if_cond(
                    ConditionExpr::identifier("disabled"),
                    "show",
                )],
            },
        );
        fragments.insert(
            "show".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("disabled!")],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"isDisabled": true});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-comp disabled>disabled!</my-comp>"
        );
    }

    // ===== HTML Escape Tests (ported from utils.test.js escapeHtml) =====

    /// Helper: render a signal value through the handler and return the escaped output.
    fn render_signal(value: &str) -> String {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::signal("v", false)],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"v": value});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        writer.get_content()
    }

    #[test]
    fn test_escape_ampersand() {
        assert_eq!(render_signal("&"), "&amp;");
    }

    #[test]
    fn test_escape_less_than() {
        assert_eq!(render_signal("<"), "&lt;");
    }

    #[test]
    fn test_escape_greater_than() {
        assert_eq!(render_signal(">"), "&gt;");
    }

    #[test]
    fn test_escape_double_quote() {
        assert_eq!(render_signal("\""), "&quot;");
    }

    #[test]
    fn test_escape_single_quote() {
        // encode_safe escapes ' as &#x27;
        let result = render_signal("'");
        assert_eq!(
            result, "&#x27;",
            "Expected &#x27; for single quote, got: {result}"
        );
    }

    #[test]
    fn test_escape_multiple_special_chars() {
        let result = render_signal("<script>alert('xss');</script>");
        assert!(
            result.contains("&lt;") && result.contains("&gt;"),
            "Expected escaped HTML, got: {}",
            result
        );
        assert!(
            !result.contains("<script>"),
            "Should not contain raw <script> tag"
        );
    }

    #[test]
    fn test_escape_no_special_chars() {
        assert_eq!(render_signal("Hello World"), "Hello World");
    }

    #[test]
    fn test_escape_empty_string() {
        assert_eq!(render_signal(""), "");
    }

    #[test]
    fn test_escape_special_at_beginning() {
        let result = render_signal("<Hello");
        assert!(
            result.starts_with("&lt;"),
            "Expected &lt; at start, got: {}",
            result
        );
    }

    #[test]
    fn test_escape_special_at_end() {
        let result = render_signal("Hello>");
        assert!(
            result.ends_with("&gt;"),
            "Expected &gt; at end, got: {}",
            result
        );
    }

    #[test]
    fn test_escape_special_in_middle() {
        let result = render_signal("Hel&lo");
        assert!(
            result.contains("&amp;"),
            "Expected &amp; in middle, got: {}",
            result
        );
    }

    // ── GROUP 5: Boolean Attribute Edge Cases ─────────────────────────

    #[test]
    fn test_boolean_attr_truthy_values() {
        // checked: 1
        {
            let mut fragments = HashMap::new();
            fragments.insert(
                "index.html".to_string(),
                FragmentList {
                    fragments: vec![
                        webhubFragment::raw("<input"),
                        webhubFragment::attribute_boolean(
                            "checked",
                            ConditionExpr::identifier("checked"),
                        ),
                        webhubFragment::raw(">"),
                    ],
                },
            );
            let protocol = webhubProtocol::new(fragments);
            let state = test_json!({"checked": 1});
            let mut writer = TestWriter::new();
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();
            assert_eq!(writer.get_content(), "<input checked>");
        }
        // checked: "yes"
        {
            let mut fragments = HashMap::new();
            fragments.insert(
                "index.html".to_string(),
                FragmentList {
                    fragments: vec![
                        webhubFragment::raw("<input"),
                        webhubFragment::attribute_boolean(
                            "checked",
                            ConditionExpr::identifier("checked"),
                        ),
                        webhubFragment::raw(">"),
                    ],
                },
            );
            let protocol = webhubProtocol::new(fragments);
            let state = test_json!({"checked": "yes"});
            let mut writer = TestWriter::new();
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();
            assert_eq!(writer.get_content(), "<input checked>");
        }
        // checked: {} (empty object is truthy)
        {
            let mut fragments = HashMap::new();
            fragments.insert(
                "index.html".to_string(),
                FragmentList {
                    fragments: vec![
                        webhubFragment::raw("<input"),
                        webhubFragment::attribute_boolean(
                            "checked",
                            ConditionExpr::identifier("checked"),
                        ),
                        webhubFragment::raw(">"),
                    ],
                },
            );
            let protocol = webhubProtocol::new(fragments);
            let state = test_json!({"checked": {}});
            let mut writer = TestWriter::new();
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();
            // Empty object is falsy in this expression evaluator
            assert_eq!(writer.get_content(), "<input>");
        }
        // checked: "false" (string "false" is truthy)
        {
            let mut fragments = HashMap::new();
            fragments.insert(
                "index.html".to_string(),
                FragmentList {
                    fragments: vec![
                        webhubFragment::raw("<input"),
                        webhubFragment::attribute_boolean(
                            "checked",
                            ConditionExpr::identifier("checked"),
                        ),
                        webhubFragment::raw(">"),
                    ],
                },
            );
            let protocol = webhubProtocol::new(fragments);
            let state = test_json!({"checked": "false"});
            let mut writer = TestWriter::new();
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();
            assert_eq!(writer.get_content(), "<input checked>");
        }
    }

    #[test]
    fn test_boolean_attr_falsy_values() {
        // checked: 0
        {
            let mut fragments = HashMap::new();
            fragments.insert(
                "index.html".to_string(),
                FragmentList {
                    fragments: vec![
                        webhubFragment::raw("<input"),
                        webhubFragment::attribute_boolean(
                            "checked",
                            ConditionExpr::identifier("checked"),
                        ),
                        webhubFragment::raw(">"),
                    ],
                },
            );
            let protocol = webhubProtocol::new(fragments);
            let state = test_json!({"checked": 0});
            let mut writer = TestWriter::new();
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();
            assert_eq!(writer.get_content(), "<input>");
        }
        // checked: ""
        {
            let mut fragments = HashMap::new();
            fragments.insert(
                "index.html".to_string(),
                FragmentList {
                    fragments: vec![
                        webhubFragment::raw("<input"),
                        webhubFragment::attribute_boolean(
                            "checked",
                            ConditionExpr::identifier("checked"),
                        ),
                        webhubFragment::raw(">"),
                    ],
                },
            );
            let protocol = webhubProtocol::new(fragments);
            let state = test_json!({"checked": ""});
            let mut writer = TestWriter::new();
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();
            assert_eq!(writer.get_content(), "<input>");
        }
        // checked: false
        {
            let mut fragments = HashMap::new();
            fragments.insert(
                "index.html".to_string(),
                FragmentList {
                    fragments: vec![
                        webhubFragment::raw("<input"),
                        webhubFragment::attribute_boolean(
                            "checked",
                            ConditionExpr::identifier("checked"),
                        ),
                        webhubFragment::raw(">"),
                    ],
                },
            );
            let protocol = webhubProtocol::new(fragments);
            let state = test_json!({"checked": false});
            let mut writer = TestWriter::new();
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();
            assert_eq!(writer.get_content(), "<input>");
        }
        // no checked key at all
        {
            let mut fragments = HashMap::new();
            fragments.insert(
                "index.html".to_string(),
                FragmentList {
                    fragments: vec![
                        webhubFragment::raw("<input"),
                        webhubFragment::attribute_boolean(
                            "checked",
                            ConditionExpr::identifier("checked"),
                        ),
                        webhubFragment::raw(">"),
                    ],
                },
            );
            let protocol = webhubProtocol::new(fragments);
            let state = test_json!({});
            let mut writer = TestWriter::new();
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();
            assert_eq!(writer.get_content(), "<input>");
        }
    }

    #[test]
    fn test_boolean_attr_expression_true() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<button"),
                    webhubFragment::attribute_boolean(
                        "disabled",
                        ConditionExpr::predicate("itemCount", ComparisonOperator::Equal, "5"),
                    ),
                    webhubFragment::raw(">Click</button>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"itemCount": 5});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "<button disabled>Click</button>");
    }

    #[test]
    fn test_boolean_attr_expression_false() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<button"),
                    webhubFragment::attribute_boolean(
                        "disabled",
                        ConditionExpr::predicate("itemCount", ComparisonOperator::Equal, "5"),
                    ),
                    webhubFragment::raw(">Click</button>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"itemCount": 3});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "<button>Click</button>");
    }

    // ── GROUP 6: Mixed Attributes ─────────────────────────────────────

    #[test]
    fn test_nested_component_attr_capture() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<parent-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                template: "parent-title".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("parent-component"),
                    webhubFragment::raw("</parent-component>"),
                ],
            },
        );
        fragments.insert(
            "parent-title".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("Hello "),
                    webhubFragment::signal("who", false),
                ],
            },
        );
        fragments.insert(
            "parent-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<child-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                template: "child-title".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("child-component"),
                    webhubFragment::raw("</child-component>"),
                ],
            },
        );
        fragments.insert(
            "child-title".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("Child of "),
                    webhubFragment::signal("title", false),
                ],
            },
        );
        fragments.insert(
            "child-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"who": "<world>"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<parent-component title=\"Hello &lt;world&gt;\"><child-component title=\"Child of Hello &lt;world&gt;\"><span>Child of Hello &lt;world&gt;</span></child-component></parent-component>"
        );
    }

    #[test]
    fn test_grandchild_attr_propagation() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<parent-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                template: "p-title".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("parent-component"),
                    webhubFragment::raw("</parent-component>"),
                ],
            },
        );
        fragments.insert(
            "p-title".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("P:"), webhubFragment::signal("p", false)],
            },
        );
        fragments.insert(
            "parent-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<child-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                template: "c-title".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("child-component"),
                    webhubFragment::raw("</child-component>"),
                ],
            },
        );
        fragments.insert(
            "c-title".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("C("),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw(")-"),
                    webhubFragment::signal("cExtra", false),
                ],
            },
        );
        fragments.insert(
            "child-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<grandchild-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                value: "title".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("grandchild-component"),
                    webhubFragment::raw("</grandchild-component>"),
                ],
            },
        );
        fragments.insert(
            "grandchild-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"p": "<p>", "cExtra": "x&y"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<parent-component title=\"P:&lt;p&gt;\"><child-component title=\"C(P:&lt;p&gt;)-x&amp;y\"><grandchild-component title=\"C(P:&lt;p&gt;)-x&amp;y\"><span>C(P:&lt;p&gt;)-x&amp;y</span></grandchild-component></child-component></parent-component>"
        );
    }

    #[test]
    fn test_for_loop_component_attr() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<parent-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                template: "parent-title-loop".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("parent-component"),
                    webhubFragment::raw("</parent-component>"),
                ],
            },
        );
        fragments.insert(
            "parent-title-loop".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("Parent:"),
                    webhubFragment::signal("who", false),
                ],
            },
        );
        fragments.insert(
            "parent-component".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::for_loop("item", "items", "child-loop")],
            },
        );
        fragments.insert(
            "child-loop".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<child-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                template: "child-title-loop".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("child-component"),
                    webhubFragment::raw("</child-component>"),
                ],
            },
        );
        fragments.insert(
            "child-title-loop".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("Hi "),
                    webhubFragment::signal("item.name", false),
                    webhubFragment::raw(" / "),
                    webhubFragment::signal("title", false),
                ],
            },
        );
        fragments.insert(
            "child-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"who": "Bob", "items": [{"name": "A<1>"}, {"name": "B&2"}]});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<parent-component title=\"Parent:Bob\"><child-component title=\"Hi A&lt;1&gt; &#x2F; Parent:Bob\"><span>Hi A&lt;1&gt; &#x2F; Parent:Bob</span></child-component><child-component title=\"Hi B&amp;2 &#x2F; Parent:Bob\"><span>Hi B&amp;2 &#x2F; Parent:Bob</span></child-component></parent-component>"
        );
    }

    #[test]
    fn test_multiple_template_attrs() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                template: "attr-title".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "data-title".into(),
                                template: "attr-data-title".into(),
                                attr_start: false,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "aria-label".into(),
                                template: "attr-aria-label".into(),
                                attr_start: false,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</my-component>"),
                ],
            },
        );
        fragments.insert(
            "attr-title".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("T:"), webhubFragment::signal("t", false)],
            },
        );
        fragments.insert(
            "attr-data-title".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("D:"), webhubFragment::signal("d", false)],
            },
        );
        fragments.insert(
            "attr-aria-label".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("A:"), webhubFragment::signal("a", false)],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("|"),
                    webhubFragment::signal("dataTitle", false),
                    webhubFragment::raw("|"),
                    webhubFragment::signal("ariaLabel", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"t": "<t&1>", "d": "d<2>", "a": "a&3"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-component title=\"T:&lt;t&amp;1&gt;\" data-title=\"D:d&lt;2&gt;\" aria-label=\"A:a&amp;3\"><span>T:&lt;t&amp;1&gt;|D:d&lt;2&gt;|A:a&amp;3</span></my-component>"
        );
    }

    #[test]
    fn test_attr_priority_over_global() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                value: "Attribute Title".into(),
                                raw_value: true,
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</my-component>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"title": "Global Title"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-component title=\"Attribute Title\"><span>Attribute Title</span></my-component>"
        );
    }

    #[test]
    fn test_attr_priority_over_local_and_global() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::for_loop("item", "items", "loop")],
            },
        );
        fragments.insert(
            "loop".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                value: "Attribute Title".into(),
                                raw_value: true,
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</my-component>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"title": "Global Title", "items": [{"title": "Local Title"}]});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-component title=\"Attribute Title\"><span>Attribute Title</span></my-component>"
        );
    }

    #[test]
    fn test_boolean_attr_first_component_attr() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "disabled".into(),
                                attr_start: true,
                                condition_tree: Some(ConditionExpr::identifier("isDisabled")),
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "label".into(),
                                value: "Component Label".into(),
                                raw_value: true,
                                attr_start: false,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</my-component>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::if_cond(
                        ConditionExpr::identifier("disabled"),
                        "disabledTemplate",
                    ),
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("label", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        fragments.insert(
            "disabledTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>Disabled</div>")],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"isDisabled": true});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-component disabled label=\"Component Label\"><div>Disabled</div><span>Component Label</span></my-component>"
        );
    }

    #[test]
    fn test_hyphenated_attr_camelcase() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "key-hyphen".into(),
                                value: "Local Value".into(),
                                raw_value: true,
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</my-component>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("keyHyphen", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"keyHyphen": "Global Value"});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-component key-hyphen=\"Local Value\"><span>Local Value</span></my-component>"
        );
    }

    #[test]
    fn test_skipped_component_attrs() {
        // Skipped attributes: class, style, role, data-*, aria-*
        // Plus framework-specific prefixes/names that the parser marks with attr_skip.
        // These render on the HTML element but are NOT passed into component attribute state.
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<test-component"),
                    // Skipped: class
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "class".into(),
                                value: "skippedClass".into(),
                                attr_start: true,
                                attr_skip: true,
                                ..Default::default()
                            },
                        )),
                    },
                    // Skipped: style
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "style".into(),
                                value: "skippedStyle".into(),
                                attr_skip: true,
                                ..Default::default()
                            },
                        )),
                    },
                    // Skipped: role
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "role".into(),
                                value: "skippedRole".into(),
                                attr_skip: true,
                                ..Default::default()
                            },
                        )),
                    },
                    // Skipped: data-testid (data-* prefix)
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "data-testid".into(),
                                value: "skippedDataTestid".into(),
                                attr_skip: true,
                                ..Default::default()
                            },
                        )),
                    },
                    // Skipped: aria-label (aria-* prefix)
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "aria-label".into(),
                                value: "skippedAriaLabel".into(),
                                attr_skip: true,
                                ..Default::default()
                            },
                        )),
                    },
                    // NOT skipped: title
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                value: "title".into(),
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("test-component"),
                    webhubFragment::raw("</test-component>"),
                ],
            },
        );
        fragments.insert(
            "test-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("class", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("style", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("role", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("dataTestid", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("ariaLabel", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "title": "Hello",
            "skippedClass": "my-class",
            "skippedStyle": "color:red",
            "skippedRole": "button",
            "skippedDataTestid": "test-id",
            "skippedAriaLabel": "label-text"
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        // Skipped attrs render on the element but their values are NOT accessible inside the component.
        // The component's signals for skipped attrs resolve to empty strings.
        // Only "title" (non-skipped) is accessible.
        assert_eq!(
            writer.get_content(),
            "<test-component class=\"my-class\" style=\"color:red\" role=\"button\" data-testid=\"test-id\" aria-label=\"label-text\" title=\"Hello\"><span>Hello-----</span></test-component>"
        );
    }

    // ── GROUP 7: Attribute Inheritance ─────────────────────────────────

    #[test]
    fn test_attr_inherit_parent_to_child() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<parent-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                value: "Parent Title".into(),
                                raw_value: true,
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("parent-component"),
                    webhubFragment::raw("</parent-component>"),
                ],
            },
        );
        fragments.insert(
            "parent-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<h1>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</h1><child-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                value: "title".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("child-component"),
                    webhubFragment::raw("</child-component>"),
                ],
            },
        );
        fragments.insert(
            "child-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<h2>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</h2>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<parent-component title=\"Parent Title\"><h1>Parent Title</h1><child-component title=\"Parent Title\"><h2>Parent Title</h2></child-component></parent-component>"
        );
    }

    #[test]
    fn test_attr_inherit_deep() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<parent-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                value: "Parent Title".into(),
                                raw_value: true,
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("parent-component"),
                    webhubFragment::raw("</parent-component>"),
                ],
            },
        );
        fragments.insert(
            "parent-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<child-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                value: "Child Title".into(),
                                raw_value: true,
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("child-component"),
                    webhubFragment::raw("</child-component>"),
                ],
            },
        );
        fragments.insert(
            "child-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<grandchild-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "title".into(),
                                value: "title".into(),
                                attr_start: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("grandchild-component"),
                    webhubFragment::raw("</grandchild-component>"),
                ],
            },
        );
        fragments.insert(
            "grandchild-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<h3>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</h3>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<parent-component title=\"Parent Title\"><child-component title=\"Child Title\"><grandchild-component title=\"Child Title\"><h3>Child Title</h3></grandchild-component></child-component></parent-component>"
        );
    }

    #[test]
    fn test_complex_attr_access() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: ":item".into(),
                                value: "complexItem".into(),
                                attr_start: true,
                                complex: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</my-component>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("item.foo", false),
                    webhubFragment::raw("</span><p>"),
                    webhubFragment::signal("item.bar", false),
                    webhubFragment::raw("</p>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"complexItem": {"foo": 1, "bar": "true"}});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-component><span>1</span><p>true</p></my-component>"
        );
    }

    #[test]
    fn test_complex_attr_for_loop() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::for_loop(
                    "item",
                    "list.items",
                    "listTemplate",
                )],
            },
        );
        fragments.insert(
            "listTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: ":item".into(),
                                value: "item".into(),
                                attr_start: true,
                                complex: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::component("item_component"),
                ],
            },
        );
        fragments.insert(
            "item_component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("item.name", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"list": {"items": [{"name": "Alice"}, {"name": "Bob"}]}});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(writer.get_content(), "<span>Alice</span><span>Bob</span>");
    }

    #[test]
    fn test_complex_attr_nested_for() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::for_loop(
                    "outer",
                    "data.outer",
                    "outerTemplate",
                )],
            },
        );
        fragments.insert(
            "outerTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::for_loop(
                    "middle",
                    "outer.middle",
                    "middleTemplate",
                )],
            },
        );
        fragments.insert(
            "middleTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::for_loop(
                    "inner",
                    "middle.inner",
                    "innerTemplate",
                )],
            },
        );
        fragments.insert(
            "innerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<card"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: ":outer".into(),
                                value: "outer".into(),
                                attr_start: true,
                                complex: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: ":middle".into(),
                                value: "middle".into(),
                                attr_start: false,
                                complex: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: ":inner".into(),
                                value: "inner".into(),
                                attr_start: false,
                                complex: true,
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("card_component"),
                    webhubFragment::raw("</card>"),
                ],
            },
        );
        fragments.insert(
            "card_component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<p>"),
                    webhubFragment::signal("outer.label", false),
                    webhubFragment::raw(" / "),
                    webhubFragment::signal("middle.label", false),
                    webhubFragment::raw(" / "),
                    webhubFragment::signal("inner.label", false),
                    webhubFragment::raw("</p>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"data": {"outer": [
            {"label": "Outer1", "middle": [{"label": "Middle1", "inner": [{"label": "Inner1A"}, {"label": "Inner1B"}]}]},
            {"label": "Outer2", "middle": [{"label": "Middle2", "inner": [{"label": "Inner2A"}]}]}
        ]}});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<card><p>Outer1 / Middle1 / Inner1A</p></card><card><p>Outer1 / Middle1 / Inner1B</p></card><card><p>Outer2 / Middle2 / Inner2A</p></card>"
        );
    }

    // ── GROUP 8: Boolean Component State ──────────────────────────────

    #[test]
    fn test_bool_component_state_true() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "disabled".into(),
                                attr_start: true,
                                condition_tree: Some(ConditionExpr::identifier("isDisabled")),
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</my-component>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::if_cond(
                        ConditionExpr::identifier("disabled"),
                        "disabledTemplate",
                    ),
                    webhubFragment::if_cond(
                        ConditionExpr::negated(ConditionExpr::identifier("disabled")),
                        "enabledTemplate",
                    ),
                ],
            },
        );
        fragments.insert(
            "disabledTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<span>Disabled</span>")],
            },
        );
        fragments.insert(
            "enabledTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<span>Enabled</span>")],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"isDisabled": true});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-component disabled><span>Disabled</span></my-component>"
        );
    }

    #[test]
    fn test_bool_component_state_false() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<my-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "disabled".into(),
                                attr_start: true,
                                condition_tree: Some(ConditionExpr::identifier("isDisabled")),
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</my-component>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::if_cond(
                        ConditionExpr::identifier("disabled"),
                        "disabledTemplate",
                    ),
                    webhubFragment::if_cond(
                        ConditionExpr::negated(ConditionExpr::identifier("disabled")),
                        "enabledTemplate",
                    ),
                ],
            },
        );
        fragments.insert(
            "disabledTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<span>Disabled</span>")],
            },
        );
        fragments.insert(
            "enabledTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<span>Enabled</span>")],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"isDisabled": false});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<my-component><span>Enabled</span></my-component>"
        );
    }

    #[test]
    fn test_bool_component_state_forward() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<parent-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "disabled".into(),
                                attr_start: true,
                                condition_tree: Some(ConditionExpr::identifier("isDisabled")),
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("parent-component"),
                    webhubFragment::raw("</parent-component>"),
                ],
            },
        );
        fragments.insert(
            "parent-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::if_cond(
                        ConditionExpr::identifier("disabled"),
                        "parentDisabledTemplate",
                    ),
                    webhubFragment::raw("<child-component"),
                    webhubFragment {
                        fragment: Some(web_ui_fragment::Fragment::Attribute(
                            webhubFragmentAttribute {
                                name: "disabled".into(),
                                attr_start: true,
                                condition_tree: Some(ConditionExpr::identifier("disabled")),
                                ..Default::default()
                            },
                        )),
                    },
                    webhubFragment::raw(">"),
                    webhubFragment::component("child-component"),
                    webhubFragment::raw("</child-component>"),
                ],
            },
        );
        fragments.insert(
            "parentDisabledTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>Parent Disabled</div>")],
            },
        );
        fragments.insert(
            "child-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::if_cond(
                        ConditionExpr::identifier("disabled"),
                        "childDisabledTemplate",
                    ),
                    webhubFragment::if_cond(
                        ConditionExpr::negated(ConditionExpr::identifier("disabled")),
                        "childEnabledTemplate",
                    ),
                ],
            },
        );
        fragments.insert(
            "childDisabledTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>Child Disabled</div>")],
            },
        );
        fragments.insert(
            "childEnabledTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>Child Enabled</div>")],
            },
        );

        // Test case 1: isDisabled = true
        {
            let protocol = webhubProtocol::new(fragments.clone());
            let state = test_json!({"isDisabled": true});
            let mut writer = TestWriter::new();
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();
            assert_eq!(
                writer.get_content(),
                "<parent-component disabled><div>Parent Disabled</div><child-component disabled><div>Child Disabled</div></child-component></parent-component>"
            );
        }

        // Test case 2: isDisabled = false
        {
            let protocol = webhubProtocol::new(fragments.clone());
            let state = test_json!({"isDisabled": false});
            let mut writer = TestWriter::new();
            handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();
            assert_eq!(
                writer.get_content(),
                "<parent-component><child-component><div>Child Enabled</div></child-component></parent-component>"
            );
        }
    }

    // ── GROUP 9: Hydration (SKIP) ─────────────────────────────────────

    // TODO: test_hydration - requires FAST handler plugin integration; see plugin/fast.rs

    // ── Component tests ──────────────────────────────────────────────

    #[test]
    fn test_component_with_template() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<custom-element>"),
                    webhubFragment::component("custom-element"),
                    webhubFragment::raw("</custom-element>"),
                ],
            },
        );
        fragments.insert(
            "custom-element".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>Custom Element</div>")],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<custom-element><div>Custom Element</div></custom-element>"
        );
        assert!(writer.is_ended());
    }

    #[test]
    fn test_component_with_slots() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<custom-element appearance=\"subtle\">"),
                    webhubFragment::component("custom-element"),
                    webhubFragment::raw("Hello World</custom-element>"),
                ],
            },
        );
        fragments.insert(
            "custom-element".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<slot></slot>")],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<custom-element appearance=\"subtle\"><slot></slot>Hello World</custom-element>"
        );
        assert!(writer.is_ended());
    }

    #[test]
    fn test_multiple_nested_components() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("item", "items", "templateRepeat"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "custom-button".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<slot></slot>")],
            },
        );
        fragments.insert(
            "custom-element".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<custom-child>"),
                    webhubFragment::component("custom-child"),
                    webhubFragment::raw("</custom-child><slot></slot>"),
                ],
            },
        );
        fragments.insert(
            "custom-child".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<h1>Hello World!</h1>")],
            },
        );
        fragments.insert(
            "templateRepeat".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<custom-element>"),
                    webhubFragment::component("custom-element"),
                    webhubFragment::raw("<custom-button>"),
                    webhubFragment::component("custom-button"),
                    webhubFragment::raw("Ok</custom-button></custom-element>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"items": [{"name": "Item1"}]});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><custom-element><custom-child><h1>Hello World!</h1></custom-child><slot></slot><custom-button><slot></slot>Ok</custom-button></custom-element></div>"
        );
        assert!(writer.is_ended());
    }

    // ── Conditional tests ────────────────────────────────────────────

    #[test]
    fn test_if_with_binary_expression() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::if_cond(
                        ConditionExpr::predicate("x", ComparisonOperator::GreaterThan, "5"),
                        "if-1",
                    ),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "if-1".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<span>If 1</span>")],
            },
        );
        let protocol = webhubProtocol::new(fragments);

        // True case: x = 10 > 5
        let state_true = test_json!({"x": 10});
        let mut writer_true = TestWriter::new();
        handle(
            &protocol,
            &state_true,
            &RenderOptions::new("index.html", "/"),
            &mut writer_true,
        )
        .unwrap();
        assert_eq!(writer_true.get_content(), "<div><span>If 1</span></div>");

        // False case: x = 1 <= 5
        let state_false = test_json!({"x": 1});
        let mut writer_false = TestWriter::new();
        handle(
            &protocol,
            &state_false,
            &RenderOptions::new("index.html", "/"),
            &mut writer_false,
        )
        .unwrap();
        assert_eq!(writer_false.get_content(), "<div></div>");
    }

    #[test]
    fn test_for_if_overlapping_local_state() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("item", "items", "template1"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "template1".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::if_cond(ConditionExpr::identifier("item.flag"), "ifBlock"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "ifBlock".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("item.label", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "flag": false,
            "items": [
                {"label": "A", "flag": true},
                {"label": "B", "flag": false},
                {"label": "C", "flag": true}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><div><span>A</span></div><div></div><div><span>C</span></div></div>"
        );
    }

    #[test]
    fn test_for_if_global_flag_no_effect() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("item", "items", "template1"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "template1".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::if_cond(ConditionExpr::identifier("item.flag"), "ifBlock"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "ifBlock".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("item.label", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "item": {"flag": true},
            "items": [
                {"label": "A", "flag": false},
                {"label": "B", "flag": true},
                {"label": "C", "flag": false}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><div></div><div><span>B</span></div><div></div></div>"
        );
    }

    // ── Recursive template test ──────────────────────────────────────

    #[test]
    fn test_recursive_template_refs() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::for_loop("item", "items", "static")],
            },
        );
        fragments.insert(
            "static".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div expanded=\""),
                    webhubFragment::signal("item.expanded", false),
                    webhubFragment::raw("\" class=\""),
                    webhubFragment::signal("testScenario", false),
                    webhubFragment::raw("\"><span>"),
                    webhubFragment::signal("item.name", false),
                    webhubFragment::raw("</span>"),
                    webhubFragment::for_loop("item", "item.children", "static"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "testScenario": "RecursiveTemplatesWithGlobalState",
            "items": [
                {"name": "A", "expanded": "false", "children": []},
                {"name": "B", "expanded": "true", "children": [
                    {"name": "C", "expanded": "false"},
                    {"name": "D", "expanded": "false"}
                ]},
                {"name": "E", "expanded": "false"}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div expanded=\"false\" class=\"RecursiveTemplatesWithGlobalState\"><span>A</span></div><div expanded=\"true\" class=\"RecursiveTemplatesWithGlobalState\"><span>B</span><div expanded=\"false\" class=\"RecursiveTemplatesWithGlobalState\"><span>C</span></div><div expanded=\"false\" class=\"RecursiveTemplatesWithGlobalState\"><span>D</span></div></div><div expanded=\"false\" class=\"RecursiveTemplatesWithGlobalState\"><span>E</span></div>"
        );
    }

    // ── Advanced state management tests ──────────────────────────────

    #[test]
    fn test_component_in_for_no_local_access() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("item", "items", "templateComponent"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "templateComponent".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<component-tag>"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</component-tag>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("name", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"items": [{"name": "Item1"}, {"name": "Item2"}]});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><component-tag><span></span></component-tag><component-tag><span></span></component-tag></div>"
        );
    }

    #[test]
    fn test_nested_for_hierarchical_state() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("outerItem", "outerItems", "outerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "outerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<section>"),
                    webhubFragment::signal("globalPrefix", false),
                    webhubFragment::signal("outerItem.outerLabel", false),
                    webhubFragment::for_loop("innerItem", "outerItem.innerItems", "innerTemplate"),
                    webhubFragment::raw("</section>"),
                ],
            },
        );
        fragments.insert(
            "innerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<p>"),
                    webhubFragment::signal("globalPrefix", false),
                    webhubFragment::signal("outerItem.outerLabel", false),
                    webhubFragment::raw(": "),
                    webhubFragment::signal("innerItem.innerLabel", false),
                    webhubFragment::raw("</p>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "globalPrefix": "Prefix: ",
            "outerItems": [
                {"outerLabel": "O1", "innerItems": [{"innerLabel": "I1"}, {"innerLabel": "I2"}]},
                {"outerLabel": "O2", "innerItems": [{"innerLabel": "I3"}]}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><section>Prefix: O1<p>Prefix: O1: I1</p><p>Prefix: O1: I2</p></section><section>Prefix: O2<p>Prefix: O2: I3</p></section></div>"
        );
    }

    #[test]
    fn test_component_in_for_global_only() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("item", "items", "templateComponent"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "templateComponent".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<component-tag>"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</component-tag>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("name", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("globalSuffix", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state =
            test_json!({"globalSuffix": "Global", "items": [{"name": "Item1"}, {"name": "Item2"}]});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><component-tag><span>-Global</span></component-tag><component-tag><span>-Global</span></component-tag></div>"
        );
    }

    #[test]
    fn test_component_no_item_moniker() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("item", "items", "templateComponent"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "templateComponent".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<component-tag>"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</component-tag>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("item.name", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("globalSuffix", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state =
            test_json!({"globalSuffix": "Global", "items": [{"name": "Item1"}, {"name": "Item2"}]});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><component-tag><span>-Global</span></component-tag><component-tag><span>-Global</span></component-tag></div>"
        );
    }

    #[test]
    fn test_for_nonqualified_uses_global() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("item", "items", "template1"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "template1".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("name", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({"name": "GlobalName", "items": [{"name": "LocalName1"}, {"name": "LocalName2"}]});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><span>GlobalName</span><span>GlobalName</span></div>"
        );
    }

    #[test]
    fn test_nested_for_if_interleaved() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("outerItem", "outerItems", "outerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "outerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<section>"),
                    webhubFragment::signal("globalPrefix", false),
                    webhubFragment::signal("outerItem.outerLabel", false),
                    webhubFragment::if_cond(
                        ConditionExpr::identifier("outerItem.include"),
                        "ifTemplate",
                    ),
                    webhubFragment::raw("</section>"),
                ],
            },
        );
        fragments.insert(
            "ifTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("innerItem", "outerItem.innerItems", "innerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "innerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<p>"),
                    webhubFragment::signal("globalSuffix", false),
                    webhubFragment::raw(": "),
                    webhubFragment::signal("innerItem.innerLabel", false),
                    webhubFragment::raw("</p>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "globalPrefix": "Prefix: ",
            "globalSuffix": "Suffix",
            "outerItems": [
                {"outerLabel": "O1", "include": true, "innerItems": [{"innerLabel": "I1"}, {"innerLabel": "I2"}]},
                {"outerLabel": "O2", "include": false, "innerItems": [{"innerLabel": "Iignored"}]},
                {"outerLabel": "O3", "include": true, "innerItems": [{"innerLabel": "I3"}]}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><section>Prefix: O1<div><p>Suffix: I1</p><p>Suffix: I2</p></div></section><section>Prefix: O2</section><section>Prefix: O3<div><p>Suffix: I3</p></div></section></div>"
        );
    }

    #[test]
    fn test_nested_for_if_outer_state() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("outerItem", "outerItems", "outerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "outerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<section>"),
                    webhubFragment::signal("globalPrefix", false),
                    webhubFragment::signal("outerItem.label", false),
                    webhubFragment::for_loop(
                        "middleItem",
                        "outerItem.middleItems",
                        "middleTemplate",
                    ),
                    webhubFragment::raw("</section>"),
                ],
            },
        );
        fragments.insert(
            "middleTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::if_cond(
                        ConditionExpr::identifier("outerItem.active"),
                        "ifTemplate",
                    ),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "ifTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<p>"),
                    webhubFragment::signal("middleItem.value", false),
                    webhubFragment::raw("</p>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "globalPrefix": "GP-",
            "outerItems": [
                {"label": "O1", "active": true, "middleItems": [{"value": "M1"}, {"value": "M2"}]},
                {"label": "O2", "active": false, "middleItems": [{"value": "M3"}]},
                {"label": "O3", "active": true, "middleItems": [{"value": "M4"}]}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><section>GP-O1<div><p>M1</p></div><div><p>M2</p></div></section><section>GP-O2<div></div></section><section>GP-O3<div><p>M4</p></div></section></div>"
        );
    }

    #[test]
    fn test_nested_for_if_inner_state() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("outerItem", "outerItems", "outerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "outerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<section>"),
                    webhubFragment::signal("outerItem.label", false),
                    webhubFragment::for_loop("innerItem", "outerItem.innerItems", "innerTemplate"),
                    webhubFragment::raw("</section>"),
                ],
            },
        );
        fragments.insert(
            "innerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<article>"),
                    webhubFragment::if_cond(
                        ConditionExpr::identifier("innerItem.show"),
                        "ifTemplate",
                    ),
                    webhubFragment::raw("</article>"),
                ],
            },
        );
        fragments.insert(
            "ifTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<p>"),
                    webhubFragment::signal("innerItem.detail", false),
                    webhubFragment::raw("</p>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "outerItems": [
                {"label": "Outer1", "innerItems": [{"detail": "Detail1", "show": true}, {"detail": "Detail2", "show": false}]},
                {"label": "Outer2", "innerItems": [{"detail": "Detail3", "show": true}]}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><section>Outer1<article><p>Detail1</p></article><article></article></section><section>Outer2<article><p>Detail3</p></article></section></div>"
        );
    }

    #[test]
    fn test_for_merge_local_global_monikers() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("item", "items", "template1"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "template1".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("item.name", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("item.globalValue", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("item.localOnly", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("item.otherVal", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "item": {"globalValue": "GLOBAL", "otherVal": "other"},
            "items": [
                {"name": "Local1", "globalValue": "LOCAL", "localOnly": "Only1"},
                {"name": "Local2", "localOnly": "Only2"}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><span>Local1-LOCAL-Only1-other</span><span>Local2-GLOBAL-Only2-other</span></div>"
        );
    }

    #[test]
    fn test_component_in_for_global_moniker_shadow() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("item", "items", "templateComponent"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "templateComponent".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<component-tag>"),
                    webhubFragment::component("my-component"),
                    webhubFragment::raw("</component-tag>"),
                ],
            },
        );
        fragments.insert(
            "my-component".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<span>"),
                    webhubFragment::signal("name", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("item.globalValue", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("localOnly", false),
                    webhubFragment::raw("-"),
                    webhubFragment::signal("item.otherVal", false),
                    webhubFragment::raw("</span>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "item": {"globalValue": "GLOBAL", "otherVal": "other"},
            "items": [
                {"name": "Local1", "globalValue": "LOCAL", "localOnly": "Only1"},
                {"name": "Local2", "localOnly": "Only2"}
            ]
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><component-tag><span>-GLOBAL--other</span></component-tag><component-tag><span>-GLOBAL--other</span></component-tag></div>"
        );
    }

    #[test]
    fn test_if_in_nested_for_local_flag() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("outer", "list.outer_items", "outerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "outerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<section>"),
                    webhubFragment::for_loop("inner_item", "outer.inner_items", "innerTemplate"),
                    webhubFragment::raw("</section>"),
                ],
            },
        );
        fragments.insert(
            "innerTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::if_cond(
                    ConditionExpr::identifier("inner_item.flag"),
                    "ifInner",
                )],
            },
        );
        fragments.insert(
            "ifInner".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<p>"),
                    webhubFragment::signal("inner_item.value", false),
                    webhubFragment::raw("</p>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "list": {"outer_items": [{"inner_items": [{"flag": true, "value": "X"}, {"flag": false, "value": "Y"}]}]},
            "inner_item": {"flag": false}
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><section><p>X</p></section></div>"
        );
    }

    #[test]
    fn test_if_in_nested_for_global_fallback() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("outer", "list.outer_items", "outerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "outerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<section>"),
                    webhubFragment::for_loop("inner_item", "outer.inner_items", "innerTemplate"),
                    webhubFragment::raw("</section>"),
                ],
            },
        );
        fragments.insert(
            "innerTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::if_cond(
                    ConditionExpr::identifier("inner_item.flag"),
                    "ifInner",
                )],
            },
        );
        fragments.insert(
            "ifInner".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<p>"),
                    webhubFragment::signal("inner_item.value", false),
                    webhubFragment::raw("</p>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "list": {"outer_items": [{"inner_items": [{"value": "X"}, {"value": "Y"}]}]},
            "inner_item": {"flag": true}
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><section><p>X</p><p>Y</p></section></div>"
        );
    }

    #[test]
    fn test_if_mixed_for_monikers() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>"),
                    webhubFragment::for_loop("outer", "list.outerItems", "outerTemplate"),
                    webhubFragment::raw("</div>"),
                ],
            },
        );
        fragments.insert(
            "outerTemplate".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<section>"),
                    webhubFragment::signal("outer.outerLabel", false),
                    webhubFragment::for_loop("inner", "outer.innerItems", "innerTemplate"),
                    webhubFragment::raw("</section>"),
                ],
            },
        );
        fragments.insert(
            "innerTemplate".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::if_cond(
                    ConditionExpr::compound(
                        ConditionExpr::identifier("outer.active"),
                        LogicalOperator::And,
                        ConditionExpr::predicate(
                            "inner.value",
                            ComparisonOperator::GreaterThan,
                            "globalLimit",
                        ),
                    ),
                    "ifInner",
                )],
            },
        );
        fragments.insert(
            "ifInner".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<p>"),
                    webhubFragment::signal("inner.value", false),
                    webhubFragment::raw("</p>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "globalLimit": 10,
            "list": {"outerItems": [
                {"outerLabel": "O1", "active": true, "innerItems": [{"value": 15}, {"value": 8}]},
                {"outerLabel": "O2", "active": false, "innerItems": [{"value": 20}]},
                {"outerLabel": "O3", "active": true, "innerItems": [{"value": 5}]}
            ]}
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        assert_eq!(
            writer.get_content(),
            "<div><section>O1<p>15</p></section><section>O2</section><section>O3</section></div>"
        );
    }

    // ── Route-aware rendering tests ─────────────────────────────────────

    fn make_route_protocol() -> webhubProtocol {
        use webhub_protocol::webhubFragmentRoute;

        let mut fragments = HashMap::new();

        // Entry page with two routes
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<h1>Shell</h1>"),
                    webhubFragment::route_from(webhubFragmentRoute {
                        path: "/".into(),
                        fragment_id: "dash-page".into(),
                        exact: true,
                        keep_alive: false,
                        ..Default::default()
                    }),
                    webhubFragment::route_from(webhubFragmentRoute {
                        path: "/contacts/:id".into(),
                        fragment_id: "detail-page".into(),
                        exact: true,
                        keep_alive: false,
                        ..Default::default()
                    }),
                ],
            },
        );

        // Dashboard page component
        fragments.insert(
            "dash-page".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Dashboard</p>")],
            },
        );

        // Detail page component
        fragments.insert(
            "detail-page".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Detail</p>")],
            },
        );

        webhubProtocol::new(fragments)
    }

    fn make_nested_route_protocol() -> webhubProtocol {
        use webhub_protocol::webhubFragmentRoute;

        let mut fragments = HashMap::new();

        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::route_from(webhubFragmentRoute {
                    path: "/".into(),
                    fragment_id: "app-shell".into(),
                    exact: false,
                    children: vec![webhubFragmentRoute {
                        path: "sections/:id".into(),
                        fragment_id: "section-comp".into(),
                        exact: false,
                        children: vec![webhubFragmentRoute {
                            path: "topics/:topicId".into(),
                            fragment_id: "topic-comp".into(),
                            exact: true,
                            children: vec![],
                            keep_alive: false,
                            ..Default::default()
                        }],
                        keep_alive: false,
                        ..Default::default()
                    }],
                    keep_alive: false,
                    ..Default::default()
                })],
            },
        );

        fragments.insert(
            "app-shell".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<h1>Shell</h1>"),
                    webhubFragment::outlet(),
                ],
            },
        );

        fragments.insert(
            "section-comp".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<h2>Section</h2>"),
                    webhubFragment::outlet(),
                ],
            },
        );

        fragments.insert(
            "topic-comp".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Topic content</p>")],
            },
        );

        webhubProtocol::new(fragments)
    }

    #[test]
    fn test_route_renders_shell_always() {
        let protocol = make_route_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        let html = writer.get_content();

        // Shell content always renders regardless of route matching
        assert!(html.contains("<h1>Shell</h1>"), "shell should render");
        // Dashboard matches "/" so it should be active
        assert!(html.contains(" active>"), "matched route should be active");
        // Detail should be hidden and empty
        assert!(
            html.contains("style=\"display:none\""),
            "non-matched routes should be hidden"
        );
    }

    #[test]
    fn test_route_matched_renders_visible() {
        let protocol = make_route_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        let html = writer.get_content();

        // Dashboard route should be visible (active, no display:none)
        assert!(
            html.contains("<webhub-route path=\"/\""),
            "dashboard route should exist"
        );
        assert!(
            html.contains("active>") && html.contains("<dash-page>"),
            "matched route should be active with component tag: {html}"
        );
        assert!(
            html.contains("<p>Dashboard</p>"),
            "matched route should have content"
        );
    }

    #[test]
    fn test_route_non_matched_renders_hidden_empty() {
        let protocol = make_route_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        let html = writer.get_content();

        // Detail route should be hidden and empty (no content rendered)
        assert!(
            html.contains("<webhub-route path=\"/contacts/:id\""),
            "detail route element should exist"
        );
        // The non-matched route should have display:none and no inner content
        let detail_start = html.find("path=\"/contacts/:id\"").expect("detail route");
        let after_detail = &html[detail_start..];
        assert!(
            after_detail.contains("style=\"display:none\">")
                && !after_detail.starts_with(&format!("path=\"/contacts/:id\"{}detail-page>", "")),
            "non-matched route should be hidden: {after_detail}"
        );
        // Should NOT contain the component's rendered content
        let detail_end = after_detail.find("</webhub-route>").expect("closing tag");
        let detail_body = &after_detail[..detail_end];
        assert!(
            !detail_body.contains("<detail-page>"),
            "non-matched route should not render component content: {detail_body}"
        );
    }

    #[test]
    fn test_route_parameterized_match() {
        let protocol = make_route_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/contacts/42"),
            &mut writer,
        )
        .unwrap();
        let html = writer.get_content();

        // Detail route matches /contacts/42
        assert!(
            html.contains("active>") && html.contains("<detail-page>"),
            "detail route should be active: {html}"
        );
        assert!(html.contains("<p>Detail</p>"), "detail should have content");
        // Dashboard should be hidden + empty
        let dash_start = html
            .find("component=\"dash-page\"")
            .expect("dashboard route");
        let after_dash = &html[dash_start..];
        assert!(
            after_dash.contains("style=\"display:none\">"),
            "dashboard should be hidden when detail matches: {after_dash}"
        );
        let dash_end = after_dash.find("</webhub-route>").expect("closing tag");
        let dash_body = &after_dash[..dash_end];
        assert!(
            !dash_body.contains("<dash-page>"),
            "dashboard should not render component content: {dash_body}"
        );
    }

    #[test]
    fn test_route_no_match_all_hidden_empty() {
        let protocol = make_route_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/nonexistent"),
            &mut writer,
        )
        .unwrap();
        let html = writer.get_content();

        // Shell content should still render
        assert!(html.contains("<h1>Shell</h1>"));
        // All routes should be hidden + empty (nothing matched)
        assert!(
            !html.contains("<p>Dashboard</p>"),
            "no route content when nothing matches"
        );
        assert!(
            !html.contains("<p>Detail</p>"),
            "no route content when nothing matches"
        );
    }

    #[test]
    fn test_route_component_attr_emitted() {
        let protocol = make_route_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        let html = writer.get_content();
        // component attribute should be emitted on webhub-route
        assert!(
            html.contains("component=\"dash-page\""),
            "component attr should be on webhub-route: {html}"
        );
        assert!(
            html.contains("component=\"detail-page\""),
            "component attr should be on webhub-route: {html}"
        );
    }

    #[test]
    fn test_no_plugin_no_state_attributes() {
        let protocol = make_route_protocol();
        let state = test_json!({
            "title": "Fish & Chips",
            "cartOpen": true,
            "items": [{"name": "A&B"}]
        });
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();
        // Without a plugin, no state attributes at all
        assert!(
            !html.contains("data-state"),
            "no data-state without plugin: {html}"
        );
        assert!(
            !html.contains(r#"title="Fish"#),
            "no scalar attrs without plugin: {html}"
        );
    }

    #[test]
    fn test_nested_routes_render_webhub_route_as_light_dom() {
        let protocol = make_nested_route_protocol();
        let state = test_json!({"title": "Test"});
        let handler = webhubHandler::new();
        let mut writer = TestWriter::new();

        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/sections/frontend"),
                &mut writer,
            )
            .expect("render failed");

        let html = writer.get_content();

        assert!(
            html.contains("component=\"app-shell\"") && html.contains("active>"),
            "root route should be active: {html}"
        );
        // webhub-route should NOT have shadow DOM — it's a light DOM structural element
        assert!(
            !html.contains("<template shadowrootmode"),
            "webhub-route should be light DOM (no shadow template): {html}"
        );
    }

    #[test]
    fn test_nested_routes_render_outlet_as_light_dom() {
        let protocol = make_nested_route_protocol();
        let state = test_json!({"title": "Test"});
        let handler = webhubHandler::new();
        let mut writer = TestWriter::new();

        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/sections/frontend"),
                &mut writer,
            )
            .expect("render failed");

        let html = writer.get_content();

        // No <webhub-outlet> wrapper — routes render directly at outlet position
        assert!(
            !html.contains("<webhub-outlet>"),
            "should not contain webhub-outlet wrapper: {html}"
        );
        // Route elements should be in the output directly
        assert!(
            html.contains("<webhub-route"),
            "should contain webhub-route elements: {html}"
        );
    }

    #[test]
    fn test_nested_routes_match_child_at_outlet() {
        let protocol = make_nested_route_protocol();
        let state = test_json!({"title": "Test"});
        let handler = webhubHandler::new();
        let mut writer = TestWriter::new();

        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/sections/frontend"),
                &mut writer,
            )
            .expect("render failed");

        let html = writer.get_content();

        assert!(
            html.contains("component=\"section-comp\"") && html.contains("active>"),
            "section route should be active: {html}"
        );
        assert!(
            html.contains("<h2>Section</h2>"),
            "section content should be present: {html}"
        );
    }

    #[test]
    fn test_nested_routes_three_levels_deep() {
        let protocol = make_nested_route_protocol();
        let state = test_json!({"title": "Test"});
        let handler = webhubHandler::new();
        let mut writer = TestWriter::new();

        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/sections/frontend/topics/react"),
                &mut writer,
            )
            .expect("render failed");

        let html = writer.get_content();

        assert!(
            html.contains("component=\"app-shell\"") && html.contains("active>"),
            "root active: {html}"
        );
        assert!(
            html.contains("component=\"section-comp\"") && html.contains("active>"),
            "section active: {html}"
        );
        assert!(
            html.contains("component=\"topic-comp\"")
                && html.contains("exact")
                && html.contains("active>"),
            "topic active: {html}"
        );
        assert!(
            html.contains("<p>Topic content</p>"),
            "leaf content present: {html}"
        );
    }

    #[test]
    fn test_nested_routes_nonmatched_siblings_hidden() {
        let protocol = make_nested_route_protocol();
        let state = test_json!({"title": "Test"});
        let handler = webhubHandler::new();
        let mut writer = TestWriter::new();

        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/sections/frontend"),
                &mut writer,
            )
            .expect("render failed");

        let html = writer.get_content();

        assert!(
            html.contains(r#"component="topic-comp" exact style="display:none">"#),
            "topic should be hidden: {html}"
        );
    }

    #[test]
    fn test_nested_routes_root_only() {
        let protocol = make_nested_route_protocol();
        let state = test_json!({"title": "Test"});
        let handler = webhubHandler::new();
        let mut writer = TestWriter::new();

        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .expect("render failed");

        let html = writer.get_content();

        assert!(
            html.contains("component=\"app-shell\"") && html.contains("active>"),
            "root active at /: {html}"
        );
        assert!(
            html.contains("<h1>Shell</h1>"),
            "shell renders at /: {html}"
        );
        assert!(
            html.contains(r#"component="section-comp" style="display:none">"#),
            "section hidden at /: {html}"
        );
    }

    // ── CSS Module dedup tests ───────────────────────────────────────

    #[test]
    fn test_css_module_emitted_once_inline_in_component() {
        // CSS module definition emitted once in the component's light DOM
        // on first render, not in <head> and not on second instance.
        let template = r#"<p><slot></slot></p>"#;

        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body><div>".to_string()),
                    webhubFragment::component("my-card"),
                    webhubFragment::raw("A".to_string()),
                    webhubFragment::component("my-card"),
                    webhubFragment::raw("B</div>".to_string()),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "my-card".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw(template.to_string())],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        protocol
            .components
            .entry("my-card".to_string())
            .or_default()
            .css = "p{color:red}".to_string();
        let state = test_json!({});
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();

        // CSS module importmap should appear exactly once
        let count = html.matches(r#"<script type="importmap""#).count();
        assert_eq!(
            count, 1,
            "CSS module importmap should be emitted once, got {count} in: {html}"
        );
        assert!(
            html.contains(r#""my-card":"data:text/css,"#),
            "Importmap must register my-card under a data: URI: {html}"
        );

        // Template content should appear twice (once per component instance)
        let tmpl_count = html.matches(r#"<p><slot></slot></p>"#).count();
        assert_eq!(
            tmpl_count, 2,
            "Template should render twice, got {tmpl_count} in: {html}"
        );

        // CSS module should be in <body> (inline), not in <head>
        let css_pos = html
            .find(r#"<script type="importmap""#)
            .expect("CSS module importmap missing");
        let body_pos = html.find("<body>").expect("<body> missing");
        assert!(
            css_pos > body_pos,
            "CSS module should be inline in component, not in <head>: {html}"
        );
    }

    #[test]
    fn test_component_without_css_renders_normally() {
        // Components without CSS module prefix pass through unchanged
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::component("my-card")],
            },
        );
        fragments.insert(
            "my-card".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw(r#"<p>hello</p>"#.to_string())],
            },
        );

        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();
        assert!(
            html.contains("<p>hello</p>"),
            "Non-module component should render normally: {html}"
        );
    }

    #[test]
    fn test_non_module_strategy_no_css_in_head() {
        // When component_css is empty (Link/Style strategies), no
        // CSS module importmap tags should appear in <head>.
        let template = r#"<p>hello</p>"#;

        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body>".to_string()),
                    webhubFragment::component("my-card"),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "my-card".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw(template.to_string())],
            },
        );

        // No component css populated — simulates Link/Style strategy
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();

        assert!(
            !html.contains(r#"<style type="module""#),
            "Non-module strategy should not emit legacy CSS module tags in <head>: {html}"
        );
        assert!(
            !html.contains(r#"<script type="importmap""#),
            "Non-module strategy should not emit CSS module importmaps in <head>: {html}"
        );
        assert!(
            html.contains("<p>hello</p>"),
            "Component should still render: {html}"
        );
    }

    #[test]
    fn test_style_strategy_embeds_inline_style_in_shadow_template() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body><my-card>".to_string()),
                    webhubFragment::component("my-card"),
                    webhubFragment::raw("</my-card></body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "my-card".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw(
                    "<template shadowrootmode=\"open\"><style>.card{color:red}</style><div>card</div></template>"
                        .to_string(),
                )],
            },
        );

        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();

        assert!(
            html.contains("<style>.card{color:red}</style>"),
            "Style strategy should embed inline CSS in shadow template: {html}"
        );
        assert!(
            !html.contains(r#"<style type="module""#),
            "Style strategy should not emit legacy module CSS in <head>: {html}"
        );
        assert!(
            !html.contains(r#"<script type="importmap""#),
            "Style strategy should not emit CSS module importmaps in <head>: {html}"
        );
    }

    #[test]
    fn test_link_strategy_light_dom_emits_stylesheet_in_head() {
        // Light DOM + Link strategy: handler emits <link rel="stylesheet">
        // in <head>. No preload tag — the stylesheet itself fetches.
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body><my-card>".to_string()),
                    webhubFragment::component("my-card"),
                    webhubFragment::raw("</my-card>".to_string()),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "my-card".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>card</div>".to_string())],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        protocol.set_css_strategy(webhub_protocol::CssStrategy::Link);
        protocol.set_dom_strategy(webhub_protocol::DomStrategy::Light);

        let comp = protocol
            .components
            .entry("my-card".to_string())
            .or_default();
        comp.css_href = "my-card.css".to_string();
        comp.template_json = r#"{"h":"<div>card</div>"}"#.to_string();

        let state = test_json!({});
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();

        let head_end = html.find("</head>").expect("</head> missing");
        let link_pos = html.find(r#"<link rel="stylesheet" href="my-card.css">"#);
        assert!(
            link_pos.is_some_and(|p| p < head_end),
            "Light DOM Link strategy should emit <link rel=stylesheet> in <head>: {html}"
        );
        assert!(
            !html.contains(r#"<link rel="preload""#),
            "Light DOM Link strategy should NOT emit preload (stylesheet already fetches): {html}"
        );
        assert!(
            !html.contains(r#"<style type="module""#),
            "Link strategy should not emit legacy module CSS: {html}"
        );
        assert!(
            !html.contains(r#"<script type="importmap""#),
            "Link strategy should not emit CSS module importmaps: {html}"
        );
    }

    #[test]
    fn test_link_strategy_shadow_dom_emits_preload_in_head() {
        // Shadow DOM + Link strategy: handler emits <link rel="preload">
        // with data-webhub-ssr-preload in <head>. No stylesheet — the shadow
        // root template already contains <link rel="stylesheet">.
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body><o-loading-state>".to_string()),
                    webhubFragment::component("o-loading-state"),
                    webhubFragment::raw("</o-loading-state><my-card>".to_string()),
                    webhubFragment::component("my-card"),
                    webhubFragment::raw("</my-card>".to_string()),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "o-loading-state".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>loading</div>".to_string())],
            },
        );
        fragments.insert(
            "my-card".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>card</div>".to_string())],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        protocol.set_css_strategy(webhub_protocol::CssStrategy::Link);
        protocol.set_dom_strategy(webhub_protocol::DomStrategy::Shadow);

        let comp1 = protocol
            .components
            .entry("o-loading-state".to_string())
            .or_default();
        comp1.css_href = "o-loading-state.css".to_string();
        comp1.template_json = r#"{"h":"<div>loading</div>"}"#.to_string();

        let comp2 = protocol
            .components
            .entry("my-card".to_string())
            .or_default();
        comp2.css_href = "my-card.css".to_string();
        comp2.template_json = r#"{"h":"<div>card</div>"}"#.to_string();

        let state = test_json!({});
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();
        let head_end = html.find("</head>").expect("</head> missing");
        let head_section = &html[..head_end];

        // Both preload hints must be present with data-webhub-ssr-preload attr
        assert!(
            head_section.contains(
                r#"<link rel="preload" href="o-loading-state.css" as="style" data-webhub-ssr-preload="style">"#
            ),
            "Missing preload for o-loading-state.css in <head>: {html}"
        );
        assert!(
            head_section.contains(
                r#"<link rel="preload" href="my-card.css" as="style" data-webhub-ssr-preload="style">"#
            ),
            "Missing preload for my-card.css in <head>: {html}"
        );
        // No stylesheet links — shadow root handles that
        assert!(
            !head_section.contains(r#"<link rel="stylesheet""#),
            "Shadow DOM should NOT emit <link rel=stylesheet> in <head>: {html}"
        );
    }

    #[test]
    fn test_link_strategy_head_links_follow_document_order() {
        // Regression for #381: Link-strategy <head> CSS <link> tags must be
        // emitted in document/traversal order, not alphabetical tag order.
        // Document order here is <z-widget> then <a-widget>; an alphabetical
        // sort would (incorrectly) place a-widget first.
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body><z-widget>".to_string()),
                    webhubFragment::component("z-widget"),
                    webhubFragment::raw("</z-widget><a-widget>".to_string()),
                    webhubFragment::component("a-widget"),
                    webhubFragment::raw("</a-widget>".to_string()),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "z-widget".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>z</div>".to_string())],
            },
        );
        fragments.insert(
            "a-widget".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>a</div>".to_string())],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        protocol.set_css_strategy(webhub_protocol::CssStrategy::Link);
        protocol.set_dom_strategy(webhub_protocol::DomStrategy::Light);

        let z = protocol
            .components
            .entry("z-widget".to_string())
            .or_default();
        z.css_href = "z-widget.css".to_string();
        z.template_json = r#"{"h":"<div>z</div>"}"#.to_string();

        let a = protocol
            .components
            .entry("a-widget".to_string())
            .or_default();
        a.css_href = "a-widget.css".to_string();
        a.template_json = r#"{"h":"<div>a</div>"}"#.to_string();

        let state = test_json!({});
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();
        let head_end = html.find("</head>").expect("</head> missing");
        let head_section = &html[..head_end];

        let z_pos = head_section
            .find(r#"<link rel="stylesheet" href="z-widget.css">"#)
            .expect("z-widget stylesheet link missing from <head>");
        let a_pos = head_section
            .find(r#"<link rel="stylesheet" href="a-widget.css">"#)
            .expect("a-widget stylesheet link missing from <head>");

        assert!(
            z_pos < a_pos,
            "CSS <link> tags must follow document order (z-widget before \
             a-widget), not alphabetical order: {html}"
        );
    }

    #[test]
    fn test_css_module_emitted_in_component_light_dom() {
        // CSS module <style> tags are emitted inline in the component's light DOM,
        // not in <head>. This keeps SSR output lean — only rendered components
        // get their style definitions.
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body><my-card>".to_string()),
                    webhubFragment::component("my-card"),
                    webhubFragment::raw("</my-card>".to_string()),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "my-card".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw(r#"<p>hi</p>"#.to_string())],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        protocol
            .components
            .entry("my-card".to_string())
            .or_default()
            .css = "p{color:red}".to_string();
        let state = test_json!({});
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();

        // CSS module importmap must be INSIDE the component tag (light DOM)
        let tag_open = html.find("<my-card>").expect("<my-card> missing");
        let css_pos = html
            .find(r#"<script type="importmap""#)
            .expect("CSS module importmap missing");
        let tag_close = html.rfind("</my-card>").expect("</my-card> missing");
        assert!(
            css_pos > tag_open && css_pos < tag_close,
            "CSS module should be inside component light DOM: {html}"
        );

        // <head> should NOT contain module styles
        let head_end = html.find("</head>").expect("</head> missing");
        assert!(
            css_pos > head_end,
            "CSS module should not be in <head>: {html}"
        );
    }

    #[test]
    fn test_css_module_emitted_for_route_components() {
        // Route components get CSS modules emitted inline in their light DOM.
        let template = r#"<h1>Dashboard</h1>"#;

        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body>".to_string()),
                    webhubFragment::route("/", "dash-page"),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "dash-page".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw(template.to_string())],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        let comp = protocol
            .components
            .entry("dash-page".to_string())
            .or_default();
        comp.css = "h1{font-size:2rem}".to_string();
        comp.template_json = r#"{"h":"<h1>Dashboard</h1>"}"#.to_string();
        let state = test_json!({});
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();

        assert!(
            html.contains(r#""dash-page":"data:text/css,h1{font-size:2rem}""#),
            "Route component should have CSS module importmap with data: URI: {html}"
        );
        assert!(
            html.contains("<h1>Dashboard</h1>"),
            "Route component should render content: {html}"
        );
    }

    #[test]
    fn test_head_css_link_skipped_for_components_without_css() {
        // Regression: components without CSS files must not get <link> tags
        // in <head>, otherwise the browser requests a 404.
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body>".to_string()),
                    webhubFragment::component("has-css"),
                    webhubFragment::component("no-css"),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "has-css".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>styled</p>".to_string())],
            },
        );
        fragments.insert(
            "no-css".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>plain</p>".to_string())],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        protocol.set_css_strategy(webhub_protocol::CssStrategy::Link);
        protocol.set_dom_strategy(webhub_protocol::DomStrategy::Light);

        // Only has-css has an external stylesheet (Link strategy)
        protocol
            .components
            .entry("has-css".to_string())
            .or_default()
            .css_href = "has-css.css".to_string();

        let state = test_json!({});
        let mut writer = TestWriter::new();

        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });
        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();

        let html = writer.get_content();
        assert!(
            html.contains(r#"<link rel="stylesheet" href="has-css.css">"#),
            "Component with CSS should get a <link rel=stylesheet> in <head>: {html}"
        );
        assert!(
            !html.contains("no-css.css"),
            "Component without CSS must NOT get a <link> in <head>: {html}"
        );
    }

    #[test]
    fn test_reachable_unrendered_components_get_templates_and_css_but_not_inventory() {
        // Simulates a page where app-shell renders cart-panel, but cart-panel
        // contains an <if> block with product-card inside. When the condition
        // is false (empty cart), product-card is NOT rendered — but it IS
        // reachable from the fragment graph. Its template metadata and CSS module
        // definition must be in the output so the client can mount it when
        // the <if> flips true. However, its bit must NOT be set in the
        // inventory — the inventory tracks what was actually rendered.
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body><app-shell>".to_string()),
                    webhubFragment::component("app-shell"),
                    webhubFragment::raw("</app-shell>".to_string()),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        // app-shell contains a cart panel
        fragments.insert(
            "app-shell".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div>Shell</div>".to_string()),
                    webhubFragment::component("cart-panel"),
                ],
            },
        );
        // cart-panel has an <if> block containing product-card
        fragments.insert(
            "cart-panel".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<aside>".to_string()),
                    webhubFragment::if_cond(ConditionExpr::identifier("hasItems"), "cart-items"),
                    webhubFragment::raw("</aside>".to_string()),
                ],
            },
        );
        // cart-items (if block body) contains product-card
        fragments.insert(
            "cart-items".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::component("product-card")],
            },
        );
        fragments.insert(
            "product-card".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>Card</div>".to_string())],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        protocol.initial_state_strategy = InitialStateStrategy::Components as i32;
        for name in ["app-shell", "cart-panel", "product-card"] {
            let comp = protocol.components.entry(name.to_string()).or_default();
            comp.template_json = format!(r#"{{"h":"<div class=\"{name}\"></div>"}}"#);
            comp.css = format!(".{name}{{display:block}}");
            if name == "cart-panel" {
                comp.hydration_mode = StateProjectionMode::Keys as i32;
                comp.hydration_keys = vec!["hasItems".to_string()];
            }
            if name == "product-card" {
                comp.template_functions = r#"[function(v,s){return !!v("ready",s)}]"#.to_string();
            }
        }

        // Render with hasItems=false — product-card should NOT be rendered
        let state = test_json!({ "hasItems": false });
        let mut writer = TestWriter::new();

        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });
        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap();

        let html = writer.get_content();

        assert!(
            html.contains(r#"<script type="application/json" id="webhub-data">"#),
            "non-executable SSR metadata should be emitted in the webhub-data block: {html}"
        );
        assert!(
            html.contains(r#""state":{"hasItems":false}"#),
            "SSR state should live in the JSON data block: {html}"
        );
        assert!(
            html.contains(r#""inventory":"#),
            "SSR inventory should live in the JSON data block: {html}"
        );
        assert!(
            !html.contains("window.__webhub={\""),
            "executable bootstrap must not embed the window.__webhub JSON literal: {html}"
        );
        assert!(
            !html.contains(r#"document.getElementById("webhub-data")"#),
            "SSR must not parse webhub-data; client packages own that lazy load: {html}"
        );
        assert!(
            !html.contains("window.__webhub=w;"),
            "executable bootstrap must not replace existing window.__webhub registrations: {html}"
        );
        assert!(
            !html.contains("w.templateFns={\""),
            "template function emission must not replace existing templateFns registrations: {html}"
        );
        assert!(
            html.contains(r#"var f=w.templateFns||(w.templateFns={});f["product-card"]=[function(v,s){return !!v("ready",s)}];"#),
            "template functions should merge into the flat templateFns registry: {html}"
        );

        // product-card template IS in the output — it's a known component
        // whose template must be available for client-side <if> activation.
        assert!(
            html.contains(r#""product-card":{"h":"<div class=\"product-card\"><\/div>"}"#),
            "product-card template should be emitted even when unrendered: {html}"
        );

        // product-card CSS module IS in the output — reachable components need
        // their stylesheet definitions for client-side <if> activation.
        assert!(
            html.contains(r#""product-card":"data:text/css,"#),
            "reachable product-card CSS module importmap should be emitted: {html}"
        );

        // app-shell and cart-panel SHOULD be in the output (they were rendered)
        assert!(
            html.contains(r#""app-shell":{"h":"<div class=\"app-shell\"><\/div>"}"#),
            "rendered app-shell template should be emitted: {html}"
        );
        assert!(
            html.contains(r#""cart-panel":{"h":"<div class=\"cart-panel\"><\/div>"}"#),
            "rendered cart-panel template should be emitted: {html}"
        );
    }

    // ── CSP nonce on CSS module importmap ───────────────────────────
    //
    // When `RenderOptions::with_nonce(...)` is set, every inline
    // `<script type="importmap">` definition emitted during SSR for a
    // component CSS module must include `nonce="VALUE"` so strict CSP
    // `script-src 'nonce-...'` policies allow it. The without-nonce case
    // is already covered by other CSS module tests (e.g.
    // `test_css_module_emitted_for_route_components`).

    #[test]
    fn test_css_module_emits_nonce_attribute_when_nonce_set() {
        // Per-component first-render path (`emit_css_module`).
        let template = r#"<h1>Dashboard</h1>"#;

        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body>".to_string()),
                    webhubFragment::route("/", "dash-page"),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "dash-page".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw(template.to_string())],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        let comp = protocol
            .components
            .entry("dash-page".to_string())
            .or_default();
        comp.css = "h1{font-size:2rem}".to_string();
        comp.template_json = r#"{"h":"<h1>Dashboard</h1>"}"#.to_string();
        let state = test_json!({});
        let mut writer = TestWriter::new();

        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/").with_nonce("test-nonce-123"),
            &mut writer,
        )
        .unwrap();

        let html = writer.get_content();

        assert!(
            html.contains(
                r#"<script type="importmap" nonce="test-nonce-123">{"imports":{"dash-page":"data:text/css,h1{font-size:2rem}"}}</script>"#
            ),
            "CSS module importmap tag should include nonce attribute in canonical order: {html}"
        );
    }

    #[test]
    fn test_unrendered_css_module_emits_nonce_attribute_when_nonce_set() {
        // Body-end emission path for reachable-but-unrendered components
        // (the second site touched by the patch). Triggered via a false
        // `<if>` block under hydration; requires the webhub plugin so the
        // body_end hook executes.
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body><app-shell>".to_string()),
                    webhubFragment::component("app-shell"),
                    webhubFragment::raw("</app-shell>".to_string()),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "app-shell".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::if_cond(
                    ConditionExpr::identifier("hasItems"),
                    "cart-items",
                )],
            },
        );
        fragments.insert(
            "cart-items".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::component("product-card")],
            },
        );
        fragments.insert(
            "product-card".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<div>Card</div>".to_string())],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        for name in ["app-shell", "product-card"] {
            let comp = protocol.components.entry(name.to_string()).or_default();
            comp.template_json = format!(r#"{{"h":"<div class=\"{name}\"></div>"}}"#);
            comp.css = format!(".{name}{{display:block}}");
        }

        // Render with hasItems=false so product-card is reachable but not
        // rendered, forcing its CSS module emission through the body_end path.
        let state = test_json!({ "hasItems": false });
        let mut writer = TestWriter::new();

        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });
        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/").with_nonce("test-nonce-123"),
                &mut writer,
            )
            .unwrap();

        let html = writer.get_content();

        assert!(
            html.contains(
                r#"<script type="importmap" nonce="test-nonce-123">{"imports":{"product-card":"data:text/css,.product-card{display:block}"}}</script>"#
            ),
            "Unrendered (body_end) CSS module importmap tag should include nonce attribute in canonical order: {html}"
        );
    }

    #[test]
    fn projected_state_excludes_non_hydration_keys() -> Result<()> {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><body><style>".to_string()),
                    webhubFragment::signal("tokens.light", true),
                    webhubFragment::raw("</style>".to_string()),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        fragments.insert(
            "app-shell".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<span>shell</span>".to_string())],
            },
        );
        let index_fragments = fragments
            .get_mut("index.html")
            .expect("index fixture should exist");
        index_fragments
            .fragments
            .insert(1, webhubFragment::component("app-shell"));
        let mut protocol = webhubProtocol::new(fragments);
        protocol.initial_state_strategy = InitialStateStrategy::Components as i32;
        // Only `name` is a hydration key. `tokens` is a server-only field
        // (used above to resolve SSR CSS variables) and is NOT in the component
        // hydration keys,
        // so projection MUST keep it out of the client state block.
        protocol.components.insert(
            "app-shell".to_string(),
            webhub_protocol::ComponentData {
                hydration_mode: StateProjectionMode::Keys as i32,
                hydration_keys: vec!["name".to_string()],
                ..Default::default()
            },
        );
        let state = test_json!({
            "name": "Alice",
            "tokens": {
                "light": "--color-brand: red;"
            }
        });
        let mut writer = TestWriter::new();
        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });
        handler.handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )?;
        let output = writer.get_content();

        // SSR still reads `tokens` to resolve the inline <style>...
        assert!(output.contains("--color-brand: red;"));
        // ...but only the hydration key reaches the client state.
        assert!(output.contains(r#""name":"Alice""#));
        assert!(!output.contains(r#""tokens""#));
        Ok(())
    }

    #[test]
    fn full_initial_strategy_preserves_complete_state() -> Result<()> {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><body>"),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "client": "visible",
            "serverOnly": "also preserved",
        });
        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });
        let mut writer = TestWriter::new();
        handler.handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )?;
        let output = writer.get_content();
        assert!(output.contains(r#""client":"visible""#));
        assert!(output.contains(r#""serverOnly":"also preserved""#));
        Ok(())
    }

    #[test]
    fn uncertain_hydration_surface_preserves_complete_state() -> Result<()> {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><body>"),
                    webhubFragment::component("app-shell"),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>"),
                ],
            },
        );
        fragments.insert(
            "app-shell".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Shell</p>")],
            },
        );
        let mut protocol = webhubProtocol::new(fragments);
        protocol.initial_state_strategy = InitialStateStrategy::Components as i32;
        protocol.components.insert(
            "app-shell".to_string(),
            webhub_protocol::ComponentData {
                hydration_mode: StateProjectionMode::All as i32,
                ..Default::default()
            },
        );
        let state = test_json!({
            "known": "value",
            "possiblyInherited": "must not be dropped",
        });
        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });
        let mut writer = TestWriter::new();
        handler.handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )?;
        let output = writer.get_content();
        assert!(output.contains(r#""known":"value""#));
        assert!(output.contains(r#""possiblyInherited":"must not be dropped""#));
        Ok(())
    }

    #[test]
    fn missing_component_projection_metadata_preserves_complete_state() -> Result<()> {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><body>"),
                    webhubFragment::component("app-shell"),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>"),
                ],
            },
        );
        fragments.insert(
            "app-shell".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Shell</p>")],
            },
        );
        let mut protocol = webhubProtocol::new(fragments);
        protocol.initial_state_strategy = InitialStateStrategy::Components as i32;
        let state = test_json!({
            "known": "value",
            "serverOnly": "must not be dropped",
        });
        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });
        let mut writer = TestWriter::new();
        handler.handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )?;
        let output = writer.get_content();
        assert!(output.contains(r#""known":"value""#));
        assert!(output.contains(r#""serverOnly":"must not be dropped""#));
        Ok(())
    }

    #[test]
    fn unknown_projection_mode_preserves_complete_state() -> Result<()> {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><body>"),
                    webhubFragment::component("app-shell"),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>"),
                ],
            },
        );
        fragments.insert(
            "app-shell".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Shell</p>")],
            },
        );
        let mut protocol = webhubProtocol::new(fragments);
        protocol.initial_state_strategy = InitialStateStrategy::Components as i32;
        protocol.components.insert(
            "app-shell".to_string(),
            webhub_protocol::ComponentData {
                hydration_mode: i32::MAX,
                ..Default::default()
            },
        );
        let state = test_json!({
            "known": "value",
            "serverOnly": "must not be dropped",
        });
        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });
        let mut writer = TestWriter::new();
        handler.handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )?;
        let output = writer.get_content();
        assert!(output.contains(r#""known":"value""#));
        assert!(output.contains(r#""serverOnly":"must not be dropped""#));
        Ok(())
    }

    #[test]
    fn legacy_navigation_keys_with_default_mode_remain_keyed() {
        let mut protocol = webhubProtocol::new(HashMap::new());
        protocol.components.insert(
            "app-shell".to_string(),
            webhub_protocol::ComponentData {
                navigation_keys: vec!["selected".to_string()],
                ..Default::default()
            },
        );

        match collect_navigation_state(&protocol, ["app-shell"]) {
            StateSelection::Keys(keys) => assert_eq!(keys, vec!["selected"]),
            StateSelection::Full => panic!("legacy navigation keys should remain projected"),
        }
    }

    #[test]
    fn empty_reachable_hydration_keys_exclude_all_state() -> Result<()> {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><body>".to_string()),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        let mut protocol = webhubProtocol::new(fragments);
        protocol.initial_state_strategy = InitialStateStrategy::Components as i32;
        let state = test_json!({
            "title": "Legacy state",
            "serverOnly": "preserved",
        });
        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });

        let mut writer = TestWriter::new();
        handler.handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )?;
        assert!(writer.get_content().contains(r#""state":{}"#));
        assert!(!writer.get_content().contains("Legacy state"));
        assert!(!writer.get_content().contains("preserved"));
        Ok(())
    }

    #[test]
    fn scriptless_component_state_is_navigation_only() -> Result<()> {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><body>"),
                    webhubFragment::component("items-page"),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>"),
                ],
            },
        );
        fragments.insert(
            "items-page".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Items</p>")],
            },
        );
        let mut protocol = webhubProtocol::new(fragments);
        protocol.initial_state_strategy = InitialStateStrategy::Components as i32;
        protocol.components.insert(
            "items-page".to_string(),
            webhub_protocol::ComponentData {
                template_json: r#"{"h":"<p>Items</p>","th":1}"#.into(),
                navigation_mode: StateProjectionMode::Keys as i32,
                navigation_keys: vec!["items".into()],
                ..Default::default()
            },
        );
        let state = test_json!({
            "items": ["STATE_SENTINEL"],
            "serverOnly": "SECRET_SENTINEL",
        });
        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });
        let mut writer = TestWriter::new();

        handler.handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )?;

        let output = writer.get_content();
        assert!(output.contains(r#""state":{}"#));
        assert!(!output.contains("STATE_SENTINEL"));
        assert!(!output.contains("SECRET_SENTINEL"));
        Ok(())
    }

    #[test]
    fn write_selected_state_projects_and_escapes() {
        // `keep` is in the sorted key set and its value contains a `</` that
        // must be escaped; `drop` is absent and must be projected out.
        let state = test_json!({
            "drop": "secret",
            "keep": "</script><b>"
        });
        let keys = ["keep"];
        let selection = StateSelection::Keys(keys.to_vec());
        let mut sink = TestWriter::new();
        write_selected_state(&mut sink, &state, &selection).unwrap();
        assert_eq!(sink.get_content(), r#"{"keep":"<\/script><b>"}"#);
    }

    #[test]
    fn write_selected_state_non_object_projection_emits_empty_object() {
        let state = test_json!("scalar state has nothing hydratable");
        let keys: [&str; 0] = [];
        let selection = StateSelection::Keys(keys.to_vec());
        let mut sink = TestWriter::new();
        write_selected_state(&mut sink, &state, &selection).unwrap();
        assert_eq!(sink.get_content(), "{}");
    }

    #[test]
    fn write_selected_state_schema_first_skips_missing_and_duplicate_keys() {
        let state = test_json!({
            "keptA": 1,
            "keptB": 2,
            "serverOnlyA": 3,
            "serverOnlyB": 4,
        });
        let keys = ["keptA", "keptA", "keptB", "missing"];
        let selection = StateSelection::Keys(keys.to_vec());
        let mut sink = TestWriter::new();
        write_selected_state(&mut sink, &state, &selection).unwrap();
        assert_eq!(sink.get_content(), r#"{"keptA":1,"keptB":2}"#);
    }

    #[test]
    fn write_selected_state_map_first_matches_schema_first_output() {
        let state = test_json!({
            "keptA": 1,
            "keptB": 2,
        });
        let keys = ["keptA", "keptB", "missingA", "missingB"];
        let selection = StateSelection::Keys(keys.to_vec());
        let mut sink = TestWriter::new();
        write_selected_state(&mut sink, &state, &selection).unwrap();
        assert_eq!(sink.get_content(), r#"{"keptA":1,"keptB":2}"#);
    }

    #[test]
    fn write_selected_state_full_preserves_and_escapes_state() {
        let state = test_json!({
            "serverOnly": "</script><b>",
            "value": 42,
        });
        let mut sink = TestWriter::new();
        write_selected_state(&mut sink, &state, &StateSelection::Full).unwrap();
        assert_eq!(
            sink.get_content(),
            r#"{"serverOnly":"<\/script><b>","value":42}"#
        );
    }

    #[test]
    fn bootstrap_state_excludes_inactive_route_hydration_keys() -> Result<()> {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><body>"),
                    webhubFragment::route_from(webhub_protocol::webhubFragmentRoute {
                        path: "/".to_string(),
                        fragment_id: "home-page".to_string(),
                        exact: true,
                        ..Default::default()
                    }),
                    webhubFragment::route_from(webhub_protocol::webhubFragmentRoute {
                        path: "/admin".to_string(),
                        fragment_id: "admin-page".to_string(),
                        exact: true,
                        ..Default::default()
                    }),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>"),
                ],
            },
        );
        fragments.insert(
            "home-page".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Home</p>")],
            },
        );
        fragments.insert(
            "admin-page".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Admin</p>")],
            },
        );

        let mut protocol = webhubProtocol::new(fragments);
        protocol.initial_state_strategy = InitialStateStrategy::Components as i32;
        protocol.components.insert(
            "home-page".to_string(),
            webhub_protocol::ComponentData {
                template_json: "{}".to_string(),
                hydration_mode: StateProjectionMode::Keys as i32,
                hydration_keys: vec!["homeTitle".to_string()],
                ..Default::default()
            },
        );
        protocol.components.insert(
            "admin-page".to_string(),
            webhub_protocol::ComponentData {
                template_json: "{}".to_string(),
                hydration_mode: StateProjectionMode::Keys as i32,
                hydration_keys: vec!["adminToken".to_string()],
                ..Default::default()
            },
        );
        let state = test_json!({
            "homeTitle": "Welcome",
            "adminToken": "TOP_SECRET_SENTINEL",
        });
        let handler = webhubHandler::with_plugin(|| {
            Box::new(crate::plugin::webhub::webhubHydrationPlugin::new())
        });
        let mut writer = TestWriter::new();
        handler.handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )?;
        let output = writer.get_content();
        assert!(output.contains(r#""homeTitle":"Welcome""#));
        assert!(!output.contains("TOP_SECRET_SENTINEL"));
        assert!(!output.contains(r#""adminToken""#));
        Ok(())
    }

    #[test]
    fn test_component_attr_name_aria() {
        // component_attr_name correctly maps ARIA attributes via the shared table
        assert_eq!(component_attr_name("aria-describedby"), "ariaDescribedBy");
        assert_eq!(component_attr_name("aria-labelledby"), "ariaLabelledBy");
        assert_eq!(
            component_attr_name("aria-activedescendant"),
            "ariaActiveDescendant"
        );
        assert_eq!(component_attr_name("aria-label"), "ariaLabel");
        assert_eq!(component_attr_name("aria-hidden"), "ariaHidden");
    }

    #[test]
    fn test_component_attr_name_html_global() {
        assert_eq!(component_attr_name("readonly"), "readOnly");
        assert_eq!(component_attr_name("tabindex"), "tabIndex");
        assert_eq!(component_attr_name("accesskey"), "accessKey");
        assert_eq!(component_attr_name("contenteditable"), "contentEditable");
        assert_eq!(component_attr_name("crossorigin"), "crossOrigin");
        assert_eq!(component_attr_name("inputmode"), "inputMode");
        assert_eq!(component_attr_name("maxlength"), "maxLength");
        assert_eq!(component_attr_name("minlength"), "minLength");
        assert_eq!(component_attr_name("novalidate"), "noValidate");
        assert_eq!(component_attr_name("formaction"), "formAction");
        assert_eq!(component_attr_name("ismap"), "isMap");
        assert_eq!(component_attr_name("usemap"), "useMap");
    }

    #[test]
    fn test_component_attr_name_strips_colon() {
        assert_eq!(component_attr_name(":readonly"), "readOnly");
        assert_eq!(component_attr_name(":aria-describedby"), "ariaDescribedBy");
        assert_eq!(component_attr_name(":data-title"), "dataTitle");
    }

    #[test]
    fn test_component_attr_name_regular() {
        assert_eq!(component_attr_name("data-title"), "dataTitle");
        assert_eq!(component_attr_name("key-hyphen"), "keyHyphen");
        assert_eq!(component_attr_name("simple"), "simple");
    }

    // ── allowed_query SSR emission tests ─────────────────────────────

    fn make_query_route_protocol() -> webhubProtocol {
        use webhub_protocol::webhubFragmentRoute;

        let mut fragments = HashMap::new();

        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::route_from(webhubFragmentRoute {
                    path: "/".into(),
                    fragment_id: "app-shell".into(),
                    exact: false,
                    children: vec![
                        webhubFragmentRoute {
                            path: "compose".into(),
                            fragment_id: "compose-page".into(),
                            exact: true,
                            allowed_query: "action,to,subject".into(),
                            keep_alive: false,
                            ..Default::default()
                        },
                        webhubFragmentRoute {
                            path: "settings".into(),
                            fragment_id: "settings-page".into(),
                            exact: true,
                            keep_alive: false,
                            ..Default::default()
                        },
                    ],
                    keep_alive: false,
                    ..Default::default()
                })],
            },
        );

        fragments.insert(
            "app-shell".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<h1>App</h1>"), webhubFragment::outlet()],
            },
        );
        fragments.insert(
            "compose-page".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Compose</p>")],
            },
        );
        fragments.insert(
            "settings-page".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw("<p>Settings</p>")],
            },
        );

        webhubProtocol::new(fragments)
    }

    #[test]
    fn test_matched_route_omits_query_attr_from_dom() {
        let protocol = make_query_route_protocol();
        let state = test_json!({});
        let handler = webhubHandler::new();
        let mut writer = TestWriter::new();

        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/compose"),
                &mut writer,
            )
            .expect("render failed");

        let html = writer.get_content();
        // query attr is no longer in DOM — it's in the SSR chain JSON instead
        assert!(
            !html.contains(r#"query="action,to,subject""#),
            "query attr should not be in DOM output (moved to SSR chain JSON): {html}"
        );
    }

    #[test]
    fn test_nonmatched_route_omits_query_attr_from_dom() {
        let protocol = make_query_route_protocol();
        let state = test_json!({});
        let handler = webhubHandler::new();
        let mut writer = TestWriter::new();

        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/settings"),
                &mut writer,
            )
            .expect("render failed");

        let html = writer.get_content();
        // query attr should not be on hidden siblings either
        assert!(
            !html.contains(r#"query="#),
            "hidden route should not have query attr: {html}"
        );
    }

    #[test]
    fn test_route_without_query_has_no_query_attr() {
        let protocol = make_query_route_protocol();
        let state = test_json!({});
        let handler = webhubHandler::new();
        let mut writer = TestWriter::new();

        handler
            .handle(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/settings"),
                &mut writer,
            )
            .expect("render failed");

        let html = writer.get_content();
        // Find the settings route element and verify it has no query attr
        let settings_idx = html
            .find(r#"component="settings-page""#)
            .expect("settings route should exist");
        let settings_tag = &html[settings_idx.saturating_sub(60)..settings_idx + 40];
        assert!(
            !settings_tag.contains("query="),
            "route without allowed_query should not emit query attr: {settings_tag}"
        );
    }

    // ── Per-render head_inject / body_inject (replaces the byte-scanner
    //    InjectingStreamingWriter approach with structural signal-based
    //    injection) ───────────────────────────────────────────────────

    fn build_head_body_protocol() -> webhubProtocol {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head><title>x</title>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw("</head><body>hello".to_string()),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        webhubProtocol::new(fragments)
    }

    #[test]
    fn head_inject_emits_at_head_end_boundary() {
        let protocol = build_head_body_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        let opts = RenderOptions::new("index.html", "/").with_head_inject("<link rel=preload>");
        handle(&protocol, &state, &opts, &mut writer).unwrap();
        let html = writer.get_content();
        // The inject must appear immediately before `</head>`.
        let inject_idx = html
            .find("<link rel=preload>")
            .expect("inject HTML missing");
        let head_close_idx = html.find("</head>").expect("</head> missing");
        assert!(
            inject_idx < head_close_idx,
            "head_inject must appear before </head>: {html}"
        );
        // No duplicate.
        assert_eq!(html.matches("<link rel=preload>").count(), 1);
    }

    #[test]
    fn body_inject_emits_at_body_end_boundary() {
        let protocol = build_head_body_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        let opts = RenderOptions::new("index.html", "/").with_body_inject("<script>lr</script>");
        handle(&protocol, &state, &opts, &mut writer).unwrap();
        let html = writer.get_content();
        let inject_idx = html
            .find("<script>lr</script>")
            .expect("inject HTML missing");
        let body_close_idx = html.find("</body>").expect("</body> missing");
        assert!(
            inject_idx < body_close_idx,
            "body_inject must appear before </body>: {html}"
        );
        assert_eq!(html.matches("<script>lr</script>").count(), 1);
    }

    #[test]
    fn injects_are_no_op_when_unset() {
        let protocol = build_head_body_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        let html = writer.get_content();
        assert!(!html.contains("<link rel=preload>"));
        assert!(!html.contains("<script>lr</script>"));
    }

    #[test]
    fn empty_inject_string_treated_as_unset() {
        let protocol = build_head_body_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        let opts = RenderOptions::new("index.html", "/")
            .with_head_inject("")
            .with_body_inject("");
        handle(&protocol, &state, &opts, &mut writer).unwrap();
        // No injection happens — empty strings are normalised to None
        // by the builder, so the output is identical to the no-options case.
        let html = writer.get_content();
        assert!(html.contains("</head>"));
        assert!(html.contains("</body>"));
    }

    #[test]
    fn inject_html_is_passed_through_verbatim() {
        // The handler does NOT escape the inject string — hosts pass
        // raw HTML they trust. This test pins that contract: a `<` in
        // the inject is emitted as-is, not encoded as `&lt;`.
        let protocol = build_head_body_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        let opts =
            RenderOptions::new("index.html", "/").with_body_inject("<script>var x=1;</script>");
        handle(&protocol, &state, &opts, &mut writer).unwrap();
        assert!(writer.get_content().contains("<script>var x=1;</script>"));
    }

    /// Both injects fire and appear at the correct structural
    /// positions. Critically, this is robust against `</head>` /
    /// `</body>` literals appearing elsewhere in the document — the
    /// signal-based emitter cannot mis-fire on byte patterns inside
    /// HTML comments, `<iframe srcdoc>`, or inline scripts (which the
    /// previous byte-scanner could).
    #[test]
    fn injects_robust_against_marker_literals_in_content() {
        let mut fragments = HashMap::new();
        // The body intentionally contains `</body>` and `</head>`
        // literals before the actual structural close — these came
        // from a (hypothetical) iframe srcdoc or comment.
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head><title>x</title>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::raw(
                        "</head><body><!-- </body> </head> --><p>hi</p>".to_string(),
                    ),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();
        let opts = RenderOptions::new("index.html", "/")
            .with_head_inject("<HEAD-INJ>")
            .with_body_inject("<BODY-INJ>");
        handle(&protocol, &state, &opts, &mut writer).unwrap();
        let html = writer.get_content();
        // The head inject sits between `<title>x</title>` and the
        // first `</head>` — the structural one, not the comment one.
        let head_inj_idx = html.find("<HEAD-INJ>").expect("head inject missing");
        let head_close_idx = html.find("</head>").expect("</head> missing");
        assert!(head_inj_idx < head_close_idx);
        // The body inject sits before the structural `</body>` — NOT
        // before the `</body>` literal in the comment (which would
        // require the inject to appear inside `<p>hi</p>` somewhere).
        let body_inj_idx = html.find("<BODY-INJ>").expect("body inject missing");
        // Find the LAST `</body>` (the structural one).
        let body_close_idx = html.rfind("</body>").expect("</body> missing");
        assert!(
            body_inj_idx < body_close_idx,
            "body_inject must precede the structural </body>: {html}"
        );
        // And the comment is preserved verbatim.
        assert!(html.contains("<!-- </body> </head> -->"));
    }

    /// Coverage-14: both `head_inject` AND `body_inject` set in the
    /// same render. Each fires at the correct structural boundary and
    /// neither leaks into the other's region.
    #[test]
    fn both_injects_fire_at_correct_boundaries() {
        let protocol = build_head_body_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        let opts = RenderOptions::new("index.html", "/")
            .with_head_inject("<META-HEAD>")
            .with_body_inject("<SCRIPT-BODY>");
        handle(&protocol, &state, &opts, &mut writer).unwrap();
        let html = writer.get_content();
        let head_idx = html.find("<META-HEAD>").expect("head inject missing");
        let head_close = html.find("</head>").expect("</head> missing");
        let body_idx = html.find("<SCRIPT-BODY>").expect("body inject missing");
        let body_close = html.find("</body>").expect("</body> missing");
        assert!(head_idx < head_close, "head_inject before </head>");
        assert!(head_close < body_idx, "body_inject after </head>");
        assert!(body_idx < body_close, "body_inject before </body>");
        assert_eq!(html.matches("<META-HEAD>").count(), 1);
        assert_eq!(html.matches("<SCRIPT-BODY>").count(), 1);
    }

    /// Coverage-15 / Bug-3 (security defense): a malformed protocol
    /// emitting `head_end` and `body_end` more than once must NOT
    /// duplicate the host inject HTML. Without the dedup guard,
    /// double-emission would amplify Security-2 (a 1 MiB inject ×
    /// 1000 duplicate signals = 1 GiB output).
    #[test]
    fn injects_dedupe_against_duplicate_signals() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<html><head>".to_string()),
                    webhubFragment::signal("head_end", true),
                    webhubFragment::signal("head_end", true), // duplicate
                    webhubFragment::signal("head_end", true), // triplicate
                    webhubFragment::raw("</head><body>".to_string()),
                    webhubFragment::signal("body_end", true),
                    webhubFragment::signal("body_end", true), // duplicate
                    webhubFragment::raw("</body></html>".to_string()),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();
        let opts = RenderOptions::new("index.html", "/")
            .with_head_inject("<HINJ>")
            .with_body_inject("<BINJ>");
        handle(&protocol, &state, &opts, &mut writer).unwrap();
        let html = writer.get_content();
        assert_eq!(
            html.matches("<HINJ>").count(),
            1,
            "head_inject must emit exactly once even with duplicate head_end signals"
        );
        assert_eq!(
            html.matches("<BINJ>").count(),
            1,
            "body_inject must emit exactly once even with duplicate body_end signals"
        );
    }

    /// Coverage-15: a Shadow-DOM / component-only protocol that has NO
    /// `<head>` / `<body>` tags must NOT emit the inject (the signals
    /// never fire). Verifies the injects are no-ops, not panics.
    #[test]
    fn injects_no_op_when_no_head_or_body_signals() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw(
                    "<my-component>hi</my-component>".to_string(),
                )],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({});
        let mut writer = TestWriter::new();
        let opts = RenderOptions::new("index.html", "/")
            .with_head_inject("<HINJ>")
            .with_body_inject("<BINJ>");
        handle(&protocol, &state, &opts, &mut writer).unwrap();
        let html = writer.get_content();
        assert!(!html.contains("<HINJ>"), "head_inject must not appear");
        assert!(!html.contains("<BINJ>"), "body_inject must not appear");
        assert!(html.contains("<my-component>"));
    }

    /// Coverage-19: the handler's `&self` is shared across threads.
    /// Two concurrent renders with different inject values must NOT
    /// cross-contaminate (each thread sees only its own inject).
    /// Per-render mutable state lives on the `webhubProcessContext`,
    /// which is stack-allocated per call.
    #[test]
    fn concurrent_renders_with_different_injects_do_not_cross_contaminate() {
        let protocol = std::sync::Arc::new(build_head_body_protocol());
        let state = std::sync::Arc::new(test_json!({}));
        let handler = std::sync::Arc::new(webhubHandler::new());

        const N_THREADS: usize = 16;
        let mut handles = Vec::with_capacity(N_THREADS);
        for tid in 0..N_THREADS {
            let h = std::sync::Arc::clone(&handler);
            let p = std::sync::Arc::clone(&protocol);
            let s = std::sync::Arc::clone(&state);
            handles.push(std::thread::spawn(move || {
                let head = format!("<HEAD-T{tid}>");
                let body = format!("<BODY-T{tid}>");
                let mut writer = TestWriter::new();
                let opts = RenderOptions::new("index.html", "/")
                    .with_head_inject(&head)
                    .with_body_inject(&body);
                h.handle(&p, &s, &opts, &mut writer).unwrap();
                let html = writer.get_content();
                // Must contain my own injects exactly once.
                assert_eq!(html.matches(&head).count(), 1);
                assert_eq!(html.matches(&body).count(), 1);
                // Must NOT contain any other thread's inject.
                for other in 0..N_THREADS {
                    if other == tid {
                        continue;
                    }
                    let other_head = format!("<HEAD-T{other}>");
                    let other_body = format!("<BODY-T{other}>");
                    assert!(
                        !html.contains(&other_head),
                        "tid {tid} saw {other}'s head_inject"
                    );
                    assert!(
                        !html.contains(&other_body),
                        "tid {tid} saw {other}'s body_inject"
                    );
                }
            }));
        }
        for h in handles {
            h.join().expect("worker panicked");
        }
    }

    /// Coverage-17: a large (1 MiB) head_inject must round-trip
    /// correctly without panic, truncation, or excessive overhead.
    /// (No size cap is enforced by the handler — the host owns the
    /// safety contract; see `with_head_inject` doc comment.)
    #[test]
    fn large_inject_roundtrips_without_truncation() {
        let protocol = build_head_body_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        let big = "x".repeat(1024 * 1024);
        let opts = RenderOptions::new("index.html", "/").with_head_inject(&big);
        handle(&protocol, &state, &opts, &mut writer).unwrap();
        let html = writer.get_content();
        assert!(
            html.contains(&big),
            "large head_inject must be present verbatim ({} bytes)",
            big.len()
        );
        // Sanity: only one copy.
        assert_eq!(html.matches(&big).count(), 1);
    }

    /// `with_nonce("")` must normalize to `None` (no `<meta>` emitted),
    /// matching the empty-string semantics of `with_head_inject` /
    /// `with_body_inject`. An empty content attribute is browser-
    /// ignored noise.
    #[test]
    fn empty_nonce_treated_as_unset() {
        let protocol = build_head_body_protocol();
        let state = test_json!({});
        let mut writer = TestWriter::new();
        let opts = RenderOptions::new("index.html", "/").with_nonce("");
        handle(&protocol, &state, &opts, &mut writer).unwrap();
        assert!(
            !writer.get_content().contains("webhub-nonce"),
            "empty nonce must not emit <meta name=\"webhub-nonce\">"
        );
    }

    /// Regression for the bug Akrosh caught: the `pub` fields on
    /// `RenderOptions` let a caller bypass the `with_*` builder
    /// normalisation, e.g.:
    ///
    /// ```ignore
    /// RenderOptions { nonce: Some(""), ..RenderOptions::new(e, p) }
    /// ```
    ///
    /// Without defensive normalisation at handler init, this would
    /// emit `<script nonce="">` on every inline script. Under a
    /// strict `Content-Security-Policy: script-src 'nonce-...'` an
    /// empty nonce is a HARD CSP failure that blocks every inline
    /// script — a complete inline-script-execution outage.
    ///
    /// The handler now treats `Some("")` identically to `None` for
    /// all three injection points (nonce / head_inject / body_inject)
    /// regardless of how the option was populated.
    #[test]
    fn empty_field_bypass_is_normalised_at_handler_init() {
        let protocol = build_head_body_protocol();
        let state = test_json!({});

        // Bypass the `with_nonce` builder by writing the field directly.
        let opts_with_empty_nonce = RenderOptions {
            nonce: Some(""),
            ..RenderOptions::new("index.html", "/")
        };
        let mut writer = TestWriter::new();
        handle(&protocol, &state, &opts_with_empty_nonce, &mut writer).unwrap();
        let html = writer.get_content();
        assert!(
            !html.contains("webhub-nonce"),
            "field-bypass empty nonce must not emit `<meta name=\"webhub-nonce\">`"
        );
        assert!(
            !html.contains("nonce=\"\""),
            "field-bypass empty nonce must not emit `nonce=\"\"` (would be a hard CSP failure)"
        );

        // Same defence for inject fields.
        let opts_with_empty_injects = RenderOptions {
            head_inject: Some(""),
            body_inject: Some(""),
            ..RenderOptions::new("index.html", "/")
        };
        let mut writer = TestWriter::new();
        handle(&protocol, &state, &opts_with_empty_injects, &mut writer).unwrap();
        // No assertion needed beyond "doesn't panic and doesn't emit
        // empty inject markers" — the head_end / body_end paths must
        // treat the empty inject as no-op the same way the builder does.
    }

    /// Regression for the deep-audit's Bug-6 claim. The for-loop hot-
    /// path optimisation (insert key once + `get_mut`-swap value
    /// in-place) was suspected of corrupting the outer scope when a
    /// nested `<for>` loop reuses the same variable name. This test
    /// proves the optimisation is correct under that condition by
    /// requiring the outer `item` to be visible before, between, and
    /// after the inner loop, with its value preserved across inner
    /// iterations.
    ///
    /// Trace through the optimisation on `outer = [A, B]`,
    /// `inner = [X, Y]` with both loops using `item` as the variable:
    ///
    ///   outer pre-insert "item": Null
    ///   iter 1: get_mut → write A
    ///     emit "outer:A"
    ///     enter inner: saved = remove("item") = Some(A)
    ///                  pre-insert "item": Null
    ///                  iter 1: write X → emit "inner:X"
    ///                  iter 2: write Y → emit "inner:Y"
    ///                  restore: insert("item", A)   ← outer's A back
    ///     emit "outer:A again"               ← reads A correctly
    ///   iter 2: get_mut → write B (overwrites the restored A,
    ///                              but that's correct — we're now
    ///                              in iter 2 of the outer loop)
    ///     emit "outer:B"
    ///     enter inner: saved = remove("item") = Some(B), …, restore B
    ///     emit "outer:B again"
    ///
    /// If the audit's claim were correct — that the outer's `get_mut`
    /// somehow held a reference past the inner loop and clobbered the
    /// restoration — we'd see corrupted values in the "outer:X again"
    /// emissions. The assertion below pins the correct sequence.
    #[test]
    fn nested_for_loops_reusing_same_variable_name_dont_corrupt_scope() {
        let mut fragments = HashMap::new();
        fragments.insert(
            "index.html".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("["),
                    webhubFragment::for_loop("item", "outer", "outer_body"),
                    webhubFragment::raw("]"),
                ],
            },
        );
        fragments.insert(
            "outer_body".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("(O="),
                    webhubFragment::signal("item.tag", false),
                    webhubFragment::for_loop("item", "inner", "inner_body"),
                    webhubFragment::raw(",O="),
                    webhubFragment::signal("item.tag", false),
                    webhubFragment::raw(")"),
                ],
            },
        );
        fragments.insert(
            "inner_body".to_string(),
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("[I="),
                    webhubFragment::signal("item.tag", false),
                    webhubFragment::raw("]"),
                ],
            },
        );
        let protocol = webhubProtocol::new(fragments);
        let state = test_json!({
            "outer": [{"tag": "A"}, {"tag": "B"}],
            "inner": [{"tag": "X"}, {"tag": "Y"}],
        });
        let mut writer = TestWriter::new();
        handle(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap();
        // Expected sequence:
        //   outer iter 1 (item=A):
        //     emit "(O=A"               ← outer A before inner
        //     inner iter 1 (item=X) emit "[I=X]"
        //     inner iter 2 (item=Y) emit "[I=Y]"
        //     emit ",O=A)"              ← outer A AFTER inner restore
        //   outer iter 2 (item=B):
        //     emit "(O=B"
        //     inner iter 1 (item=X) emit "[I=X]"
        //     inner iter 2 (item=Y) emit "[I=Y]"
        //     emit ",O=B)"
        assert_eq!(
            writer.get_content(),
            "[(O=A[I=X][I=Y],O=A)(O=B[I=X][I=Y],O=B)]",
            "outer `item` must stay bound to its iteration value across the inner loop's save/restore"
        );
    }
}
