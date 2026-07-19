// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use serde_json::json;
use serde_json::Value;
use std::collections::HashMap;
use std::hint::black_box;
use webhub_handler::plugin::fast_v2::FastV2HydrationPlugin;
use webhub_handler::{Protocol, RenderOptions, ResponseWriter, webhubHandler};
use webhub_protocol::{
    ComparisonOperator, ConditionExpr, FragmentList, LogicalOperator, webhubFragment, webhubProtocol,
};

struct BenchWriter {
    output: String,
}

impl BenchWriter {
    fn new(capacity: usize) -> Self {
        Self {
            output: String::with_capacity(capacity),
        }
    }

    fn clear(&mut self) {
        self.output.clear();
    }

    fn len(&self) -> usize {
        self.output.len()
    }
}

impl ResponseWriter for BenchWriter {
    fn write(&mut self, content: &str) -> webhub_handler::Result<()> {
        self.output.push_str(content);
        Ok(())
    }

    fn end(&mut self) -> webhub_handler::Result<()> {
        Ok(())
    }
}

fn build_state(item_count: usize) -> Value {
    let mut items = Vec::with_capacity(item_count);

    for idx in 0..item_count {
        items.push(json!({
            "id": idx,
            "name": format!("Item {}", idx),
            "enabled": idx % 2 == 0
        }));
    }

    json!({
        "title": "Benchmark Title",
        "is_disabled": false,
        "theme": "dark",
        "size": "md",
        "show_footer": true,
        "footer": "Footer Content",
        "items": items
    })
}

fn build_mixed_protocol() -> Protocol {
    let mut fragments = HashMap::new();

    fragments.insert(
        "index.html".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<section class=\"root\">"),
                webhubFragment::component("card"),
                webhubFragment::raw("</section>"),
            ],
        },
    );

    fragments.insert(
        "card".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<x-card"),
                webhubFragment::attribute("title", "title"),
                webhubFragment::attribute_template("class", "class-template"),
                webhubFragment::attribute_boolean(
                    "disabled",
                    ConditionExpr::identifier("is_disabled"),
                ),
                webhubFragment::raw(">"),
                webhubFragment::raw("<h2>"),
                webhubFragment::signal("title", false),
                webhubFragment::raw("</h2><ul>"),
                webhubFragment::for_loop("item", "items", "item-frag"),
                webhubFragment::raw("</ul>"),
                webhubFragment::if_cond(ConditionExpr::identifier("show_footer"), "footer-frag"),
                // Simulate parser-plugin payload consumed by FastV2HydrationPlugin.
                webhubFragment::plugin((3u32).to_le_bytes().to_vec()),
                webhubFragment::raw("</x-card>"),
            ],
        },
    );

    fragments.insert(
        "class-template".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("card "),
                webhubFragment::signal("theme", false),
                webhubFragment::raw(" size-"),
                webhubFragment::signal("size", false),
            ],
        },
    );

    fragments.insert(
        "item-frag".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<li"),
                webhubFragment::attribute("data-id", "item.id"),
                webhubFragment::raw(">"),
                webhubFragment::signal("item.name", false),
                webhubFragment::raw("</li>"),
            ],
        },
    );

    fragments.insert(
        "footer-frag".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<footer>"),
                webhubFragment::signal("footer", false),
                webhubFragment::raw("</footer>"),
            ],
        },
    );

    Protocol::new(webhubProtocol::new(fragments))
}

fn handler_plugin_fast_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("handler_plugin_fast");
    let protocol = build_mixed_protocol();
    let state = build_state(120);

    let baseline_handler = webhubHandler::new();
    let mut baseline_writer = BenchWriter::new(16 * 1024);
    baseline_handler
        .render(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut baseline_writer,
        )
        .unwrap_or_else(|error| panic!("baseline render failed: {error}"));
    group.throughput(Throughput::Bytes(baseline_writer.len() as u64));

    group.bench_function(BenchmarkId::new("render", "without_plugin"), |b| {
        let handler = webhubHandler::new();
        let mut writer = BenchWriter::new(16 * 1024);

        b.iter(|| {
            writer.clear();
            handler
                .render(
                    black_box(&protocol),
                    black_box(&state),
                    &RenderOptions::new("index.html", "/"),
                    &mut writer,
                )
                .unwrap_or_else(|error| panic!("render without plugin failed: {error}"));
        });
    });

    group.bench_function(BenchmarkId::new("render", "with_fast_plugin"), |b| {
        let handler = webhubHandler::with_plugin(|| Box::new(FastV2HydrationPlugin::new()));
        let mut writer = BenchWriter::new(24 * 1024);

        b.iter(|| {
            writer.clear();
            handler
                .render(
                    black_box(&protocol),
                    black_box(&state),
                    &RenderOptions::new("index.html", "/"),
                    &mut writer,
                )
                .unwrap_or_else(|error| panic!("render with fast plugin failed: {error}"));
        });
    });

    group.finish();
}

fn handler_loop_scaling_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("handler_loop_scaling");
    let protocol = build_mixed_protocol();

    for &count in &[10usize, 100, 500, 2000] {
        let state = build_state(count);

        // Pre-render to measure output size for throughput
        let handler = webhubHandler::new();
        let mut writer = BenchWriter::new(count * 80 + 1024);
        handler
            .render(
                &protocol,
                &state,
                &RenderOptions::new("index.html", "/"),
                &mut writer,
            )
            .unwrap_or_else(|error| panic!("loop scaling warmup failed for {count}: {error}"));
        group.throughput(Throughput::Bytes(writer.len() as u64));

        group.bench_with_input(BenchmarkId::new("items", count), &state, |b, st| {
            let h = webhubHandler::new();
            let mut w = BenchWriter::new(count * 80 + 1024);

            b.iter(|| {
                w.clear();
                h.render(
                    black_box(&protocol),
                    black_box(st),
                    &RenderOptions::new("index.html", "/"),
                    &mut w,
                )
                .unwrap_or_else(|error| panic!("loop scaling render failed: {error}"));
            });
        });
    }

    group.finish();
}

fn build_condition_protocol() -> Protocol {
    let mut fragments = HashMap::new();

    fragments.insert(
        "index.html".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<div class=\"conditions\">"),
                // Simple identifier condition
                webhubFragment::if_cond(ConditionExpr::identifier("isAdmin"), "admin-frag"),
                // Predicate condition (equality)
                webhubFragment::if_cond(
                    ConditionExpr::predicate("status", ComparisonOperator::Equal, "'active'"),
                    "status-frag",
                ),
                // Negated condition
                webhubFragment::if_cond(
                    ConditionExpr::negated(ConditionExpr::identifier("isDisabled")),
                    "enabled-frag",
                ),
                // Compound AND condition
                webhubFragment::if_cond(
                    ConditionExpr::compound(
                        ConditionExpr::identifier("isLoggedIn"),
                        LogicalOperator::And,
                        ConditionExpr::identifier("hasPermission"),
                    ),
                    "auth-frag",
                ),
                // Compound OR condition
                webhubFragment::if_cond(
                    ConditionExpr::compound(
                        ConditionExpr::identifier("isOwner"),
                        LogicalOperator::Or,
                        ConditionExpr::identifier("isAdmin"),
                    ),
                    "access-frag",
                ),
                webhubFragment::raw("</div>"),
            ],
        },
    );

    for (id, content) in [
        ("admin-frag", "<div class=\"admin-bar\">Admin Mode</div>"),
        ("status-frag", "<span class=\"badge\">Active</span>"),
        ("enabled-frag", "<button>Click me</button>"),
        ("auth-frag", "<nav>Authenticated Menu</nav>"),
        ("access-frag", "<div>Access granted</div>"),
    ] {
        fragments.insert(
            id.to_string(),
            FragmentList {
                fragments: vec![webhubFragment::raw(content)],
            },
        );
    }

    Protocol::new(webhubProtocol::new(fragments))
}

fn build_condition_state() -> Value {
    json!({
        "isAdmin": true,
        "status": "active",
        "isDisabled": false,
        "isLoggedIn": true,
        "hasPermission": true,
        "isOwner": false,
    })
}

fn handler_condition_variety_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("handler_condition_variety");
    let protocol = build_condition_protocol();

    let state_true = build_condition_state();
    let handler = webhubHandler::new();
    let mut writer = BenchWriter::new(1024);
    handler
        .render(
            &protocol,
            &state_true,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap_or_else(|error| panic!("condition warmup failed: {error}"));
    group.throughput(Throughput::Bytes(writer.len() as u64));

    group.bench_function("all_true", |b| {
        let h = webhubHandler::new();
        let mut w = BenchWriter::new(1024);
        b.iter(|| {
            w.clear();
            h.render(
                black_box(&protocol),
                black_box(&state_true),
                &RenderOptions::new("index.html", "/"),
                &mut w,
            )
            .unwrap_or_else(|error| panic!("condition render failed: {error}"));
        });
    });

    let state_mixed = json!({
        "isAdmin": false,
        "status": "inactive",
        "isDisabled": true,
        "isLoggedIn": true,
        "hasPermission": false,
        "isOwner": false,
    });

    group.bench_function("mixed", |b| {
        let h = webhubHandler::new();
        let mut w = BenchWriter::new(1024);
        b.iter(|| {
            w.clear();
            h.render(
                black_box(&protocol),
                black_box(&state_mixed),
                &RenderOptions::new("index.html", "/"),
                &mut w,
            )
            .unwrap_or_else(|error| panic!("condition mixed render failed: {error}"));
        });
    });

    group.finish();
}

fn build_nested_component_protocol() -> Protocol {
    let mut fragments = HashMap::new();

    fragments.insert(
        "index.html".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<!DOCTYPE html><html><body>"),
                webhubFragment::component("app"),
                webhubFragment::raw("</body></html>"),
            ],
        },
    );

    fragments.insert(
        "app".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<div class=\"app\"><header><h1>"),
                webhubFragment::signal("title", false),
                webhubFragment::raw("</h1><span>"),
                webhubFragment::signal("items.length", false),
                webhubFragment::raw(" items</span></header><ul>"),
                webhubFragment::for_loop("item", "items", "item-component"),
                webhubFragment::raw("</ul></div>"),
            ],
        },
    );

    fragments.insert(
        "item-component".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<li"),
                webhubFragment::attribute("data-id", "item.id"),
                webhubFragment::raw("><span>"),
                webhubFragment::signal("item.name", false),
                webhubFragment::raw("</span>"),
                webhubFragment::if_cond(ConditionExpr::identifier("item.enabled"), "enabled-badge"),
                webhubFragment::raw("</li>"),
            ],
        },
    );

    fragments.insert(
        "enabled-badge".to_string(),
        FragmentList {
            fragments: vec![webhubFragment::raw("<span class=\"badge\">✓</span>")],
        },
    );

    Protocol::new(webhubProtocol::new(fragments))
}

fn handler_nested_components_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("handler_nested_components");
    let protocol = build_nested_component_protocol();
    let state = build_state(50);

    let handler = webhubHandler::new();
    let mut writer = BenchWriter::new(8 * 1024);
    handler
        .render(
            &protocol,
            &state,
            &RenderOptions::new("index.html", "/"),
            &mut writer,
        )
        .unwrap_or_else(|error| panic!("nested components warmup failed: {error}"));
    group.throughput(Throughput::Bytes(writer.len() as u64));

    group.bench_function("three_levels_50_items", |b| {
        let h = webhubHandler::new();
        let mut w = BenchWriter::new(8 * 1024);
        b.iter(|| {
            w.clear();
            h.render(
                black_box(&protocol),
                black_box(&state),
                &RenderOptions::new("index.html", "/"),
                &mut w,
            )
            .unwrap_or_else(|error| panic!("nested components render failed: {error}"));
        });
    });

    group.finish();
}

fn build_signal_protocol(signal_path: &str) -> Protocol {
    let mut fragments = HashMap::new();
    fragments.insert(
        "index.html".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<div>"),
                webhubFragment::signal(signal_path, false),
                webhubFragment::raw("</div>"),
            ],
        },
    );
    Protocol::new(webhubProtocol::new(fragments))
}

fn handler_state_depth_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("handler_state_depth");

    let cases: Vec<(&str, &str, Value)> = vec![
        ("flat", "name", json!({"name": "Alice"})),
        ("depth_2", "user.name", json!({"user": {"name": "Alice"}})),
        (
            "depth_3",
            "user.profile.name",
            json!({"user": {"profile": {"name": "Alice"}}}),
        ),
        (
            "depth_5",
            "a.b.c.d.name",
            json!({"a": {"b": {"c": {"d": {"name": "Alice"}}}}}),
        ),
    ];

    for (label, path, state) in &cases {
        let protocol = build_signal_protocol(path);

        group.bench_function(*label, |b| {
            let h = webhubHandler::new();
            let mut w = BenchWriter::new(256);
            b.iter(|| {
                w.clear();
                h.render(
                    black_box(&protocol),
                    black_box(state),
                    &RenderOptions::new("index.html", "/"),
                    &mut w,
                )
                .unwrap_or_else(|error| panic!("state depth render failed for {label}: {error}"));
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    handler_plugin_fast_bench,
    handler_loop_scaling_bench,
    handler_condition_variety_bench,
    handler_nested_components_bench,
    handler_state_depth_bench
);
criterion_main!(benches);
