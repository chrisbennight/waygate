//! Small rendering helpers. Human-readable output goes to stdout; the
//! tracing layer already owns stderr.

use std::fmt::Write;

use anyhow::Result;
use rmcp::model::{JsonObject, Tool};
use serde::Serialize;

pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let s = serde_json::to_string_pretty(value)?;
    println!("{s}");
    Ok(())
}

pub fn print_tool_list(tools: &[Tool]) {
    if tools.is_empty() {
        println!("(no tools returned)");
        return;
    }
    let mut max_name = "name".len();
    for t in tools {
        max_name = max_name.max(t.name.as_ref().len());
    }
    println!("{:<width$}  description", "name", width = max_name);
    println!("{}  -----------", "-".repeat(max_name));
    for t in tools {
        let desc = t.description.as_deref().unwrap_or("");
        let trimmed = first_line(desc);
        println!("{:<width$}  {}", t.name.as_ref(), trimmed, width = max_name);
    }
}

pub fn print_tool(tool: &Tool) {
    println!("name: {}", tool.name);
    if let Some(title) = tool.title.as_deref() {
        println!("title: {title}");
    }
    if let Some(description) = tool.description.as_deref() {
        println!("description:");
        for line in description.lines() {
            println!("  {line}");
        }
    }
    print_schema("input_schema", &tool.input_schema);
    if let Some(schema) = tool.output_schema.as_deref() {
        print_schema("output_schema", schema);
    }
}

fn print_schema(label: &str, schema: &JsonObject) {
    println!("{label}:");
    match serde_json::to_string_pretty(schema) {
        Ok(s) => {
            for line in s.lines() {
                println!("  {line}");
            }
        }
        Err(e) => println!("  <failed to pretty-print: {e}>"),
    }
}

fn first_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(120));
    for ch in s.chars() {
        if ch == '\n' {
            break;
        }
        if out.chars().count() >= 120 {
            out.push('…');
            break;
        }
        let _ = out.write_char(ch);
    }
    out
}
