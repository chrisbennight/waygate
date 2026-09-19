//! Manual local measurement; no wall-clock assertions or external services.
use rmcp::model::Tool;
use std::{hint::black_box, time::Instant};
use waygate_mcp::client_schema::adapt_tool;

fn main() {
    let fixtures: Vec<Tool> =
        serde_json::from_str(include_str!("../tests/fixtures/client-schema-tools.json")).unwrap();
    // Feed the actual adapter output to the stdio fixture for manual clients.
    if std::env::args().any(|arg| arg == "--fixture") {
        let mut presented = fixtures;
        for tool in &mut presented {
            adapt_tool(tool);
        }
        println!("{}", serde_json::to_string(&presented).unwrap());
        return;
    }
    let tools: Vec<Tool> = (0..1000)
        .map(|i| {
            let mut tool = fixtures[i % fixtures.len()].clone();
            tool.name = format!("fixture.tool_{i}").into();
            tool
        })
        .collect();
    for adapt in [false, true] {
        let started = Instant::now();
        let mut bytes = 0;
        for _ in 0..100 {
            let mut view = tools.clone();
            if adapt {
                for tool in &mut view {
                    black_box(adapt_tool(tool));
                }
            }
            bytes = serde_json::to_vec(black_box(&view)).unwrap().len();
        }
        println!(
            "adapt={adapt} tools={} average_list_ms={:.3} response_bytes={bytes}",
            tools.len(),
            started.elapsed().as_secs_f64() * 10.0
        );
    }
}
