// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use std::hint::black_box;
use webhub_protocol::{
    ComparisonOperator, ConditionExpr, FragmentList, LogicalOperator, webhubFragment, webhubProtocol,
};

#[allow(dead_code)]
fn create_test_protocol() -> webhubProtocol {
    let mut fragments = HashMap::new();

    fragments.insert(
        "index.html".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("Hello, webhub!\n"),
                webhubFragment::for_loop("person", "people", "for-1"),
                webhubFragment::signal("description", true),
                webhubFragment::if_cond(ConditionExpr::identifier("contact"), "if-1"),
            ],
        },
    );

    fragments.insert(
        "for-1".to_string(),
        FragmentList {
            fragments: vec![webhubFragment::signal("person.name", false)],
        },
    );

    fragments.insert(
        "if-1".to_string(),
        FragmentList {
            fragments: vec![webhubFragment::component("contact-card")],
        },
    );

    fragments.insert(
        "contact-card".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("Hello, "),
                webhubFragment::signal("name", false),
            ],
        },
    );

    webhubProtocol::new(fragments)
}

fn create_simple_protocol() -> webhubProtocol {
    let mut fragments = HashMap::new();

    fragments.insert(
        "index.html".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("Hello, webhub!\n"),
                webhubFragment::for_loop("person", "people", "for-1"),
            ],
        },
    );

    fragments.insert(
        "for-1".to_string(),
        FragmentList {
            fragments: vec![webhubFragment::signal("person.name", false)],
        },
    );

    webhubProtocol::new(fragments)
}

fn serialize_protobuf_benchmark(c: &mut Criterion) {
    let protocol = create_simple_protocol();

    c.bench_function("serialize_protobuf", |b| {
        b.iter(|| black_box(&protocol).to_protobuf())
    });
}

fn deserialize_protobuf_benchmark(c: &mut Criterion) {
    let protocol = create_simple_protocol();
    let bytes = protocol.to_protobuf().expect("encode failed");

    c.bench_function("deserialize_protobuf", |b| {
        b.iter(|| webhubProtocol::from_protobuf(black_box(&bytes)))
    });
}

fn complex_condition_benchmark(c: &mut Criterion) {
    let nested = ConditionExpr::compound(
        ConditionExpr::predicate("user.role", ComparisonOperator::Equal, "admin"),
        LogicalOperator::And,
        ConditionExpr::negated(ConditionExpr::predicate(
            "user.disabled",
            ComparisonOperator::Equal,
            "true",
        )),
    );

    let mut fragments = HashMap::new();
    fragments.insert(
        "main".to_string(),
        FragmentList {
            fragments: vec![webhubFragment::if_cond(nested, "then")],
        },
    );
    fragments.insert(
        "then".to_string(),
        FragmentList {
            fragments: vec![webhubFragment::raw("ok")],
        },
    );
    let protocol = webhubProtocol::new(fragments);
    let bytes = protocol.to_protobuf().expect("encode failed");

    c.bench_function("deserialize_complex_condition", |b| {
        b.iter(|| webhubProtocol::from_protobuf(black_box(&bytes)))
    });
}

fn create_medium_protocol() -> webhubProtocol {
    let mut fragments = HashMap::new();

    // Root page — head + body structure
    fragments.insert(
        "index.html".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>"),
                webhubFragment::signal("title", false),
                webhubFragment::raw("</title></head><body>"),
                webhubFragment::component("app"),
                webhubFragment::raw("<script src=\"/app.js\"></script></body></html>"),
            ],
        },
    );

    // App component — header + list + footer
    fragments.insert(
        "app".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<div class=\"app\"><header><h1>"),
                webhubFragment::signal("title", false),
                webhubFragment::raw("</h1><span class=\"count\">"),
                webhubFragment::signal("remainingCount", false),
                webhubFragment::raw(" remaining</span></header><div class=\"input-row\"><input type=\"text\" placeholder=\"Add item...\"/><button>Add</button></div><ul class=\"list\">"),
                webhubFragment::for_loop("item", "items", "item-frag"),
                webhubFragment::raw("</ul>"),
                webhubFragment::if_cond(ConditionExpr::identifier("showFooter"), "footer-frag"),
                webhubFragment::raw("</div>"),
            ],
        },
    );

    // Item fragment — renders each todo item
    fragments.insert(
        "item-frag".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<li"),
                webhubFragment::attribute("data-id", "item.id"),
                webhubFragment::attribute_template("class", "item-class-tmpl"),
                webhubFragment::raw(">"),
                webhubFragment::signal("item.title", false),
                webhubFragment::if_cond(
                    ConditionExpr::predicate("item.state", ComparisonOperator::Equal, "'done'"),
                    "done-badge",
                ),
                webhubFragment::raw(
                    "<button class=\"toggle\">✓</button><button class=\"delete\">✕</button></li>",
                ),
            ],
        },
    );

    // Item class template
    fragments.insert(
        "item-class-tmpl".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("todo-item "),
                webhubFragment::signal("item.state", false),
            ],
        },
    );

    // Done badge
    fragments.insert(
        "done-badge".to_string(),
        FragmentList {
            fragments: vec![webhubFragment::raw("<span class=\"badge done\">✓</span>")],
        },
    );

    // Footer
    fragments.insert(
        "footer-frag".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<footer><p>"),
                webhubFragment::signal("footerText", false),
                webhubFragment::raw("</p><a"),
                webhubFragment::attribute("href", "helpUrl"),
                webhubFragment::raw(">Help</a></footer>"),
            ],
        },
    );

    webhubProtocol::new(fragments)
}

fn create_large_protocol(component_count: usize) -> webhubProtocol {
    let mut fragments = HashMap::new();

    // Root: nav + main with all components
    let mut root_frags = Vec::with_capacity(component_count * 2 + 4);
    root_frags.push(webhubFragment::raw("<html><body><nav>"));
    root_frags.push(webhubFragment::for_loop("link", "navLinks", "nav-link-frag"));
    root_frags.push(webhubFragment::raw("</nav><main>"));

    for idx in 0..component_count {
        let frag_id = format!("panel-{idx}");
        root_frags.push(webhubFragment::component(&frag_id));
    }

    root_frags.push(webhubFragment::raw("</main></body></html>"));

    fragments.insert(
        "index.html".to_string(),
        FragmentList {
            fragments: root_frags,
        },
    );

    // Nav link fragment
    fragments.insert(
        "nav-link-frag".to_string(),
        FragmentList {
            fragments: vec![
                webhubFragment::raw("<a"),
                webhubFragment::attribute("href", "link.url"),
                webhubFragment::attribute_boolean(
                    "disabled",
                    ConditionExpr::identifier("link.disabled"),
                ),
                webhubFragment::raw(">"),
                webhubFragment::signal("link.label", false),
                webhubFragment::raw("</a>"),
            ],
        },
    );

    // Generate panel components
    for idx in 0..component_count {
        let panel_id = format!("panel-{idx}");
        let body_id = format!("panel-body-{idx}");
        let cond_id = format!("panel-detail-{idx}");

        fragments.insert(
            panel_id,
            FragmentList {
                fragments: vec![
                    webhubFragment::raw(format!("<section class=\"panel\" data-idx=\"{idx}\">")),
                    webhubFragment::raw("<h3>"),
                    webhubFragment::signal("title", false),
                    webhubFragment::raw("</h3>"),
                    webhubFragment::component(&body_id),
                    webhubFragment::if_cond(ConditionExpr::identifier("showDetails"), &cond_id),
                    webhubFragment::raw("</section>"),
                ],
            },
        );

        fragments.insert(
            body_id,
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<div class=\"panel-body\"><p>"),
                    webhubFragment::signal("description", false),
                    webhubFragment::raw("</p><span class=\"metric\">"),
                    webhubFragment::signal("metric", false),
                    webhubFragment::raw("</span></div>"),
                ],
            },
        );

        fragments.insert(
            cond_id,
            FragmentList {
                fragments: vec![
                    webhubFragment::raw("<details><summary>More</summary><p>"),
                    webhubFragment::signal("details", false),
                    webhubFragment::raw("</p></details>"),
                ],
            },
        );
    }

    webhubProtocol::new(fragments)
}

fn serialize_medium_benchmark(c: &mut Criterion) {
    let protocol = create_medium_protocol();
    c.bench_function("serialize_medium_protobuf", |b| {
        b.iter(|| black_box(&protocol).to_protobuf())
    });
}

fn deserialize_medium_benchmark(c: &mut Criterion) {
    let protocol = create_medium_protocol();
    let bytes = protocol.to_protobuf().expect("encode failed");
    c.bench_function("deserialize_medium_protobuf", |b| {
        b.iter(|| webhubProtocol::from_protobuf(black_box(&bytes)))
    });
}

fn protocol_size_sweep_bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_size_sweep");

    for &count in &[5usize, 15, 30, 50] {
        let protocol = create_large_protocol(count);
        let bytes = protocol.to_protobuf().expect("encode failed");
        group.throughput(Throughput::Bytes(bytes.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("serialize", count),
            &protocol,
            |b, proto| {
                b.iter(|| black_box(proto).to_protobuf());
            },
        );

        group.bench_with_input(BenchmarkId::new("deserialize", count), &bytes, |b, data| {
            b.iter(|| webhubProtocol::from_protobuf(black_box(data)));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    serialize_protobuf_benchmark,
    deserialize_protobuf_benchmark,
    complex_condition_benchmark,
    serialize_medium_benchmark,
    deserialize_medium_benchmark,
    protocol_size_sweep_bench
);
criterion_main!(benches);
