//! Small rendering helpers. Human-readable output goes to stdout; the
//! tracing layer already owns stderr.

use std::fmt::Write;

use anyhow::Result;
use rmcp::model::Tool;
use serde::Serialize;

use crate::sep1888::{OperationDescriptor, OperationsResponse, TypesResponse};

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

pub fn print_operations(resp: &OperationsResponse) {
    if resp.operations.is_empty() {
        println!("(no operations matched)");
        return;
    }
    let mut max_name = "name".len();
    for op in &resp.operations {
        max_name = max_name.max(op.name.len());
    }
    println!(
        "{:<width$}  {:<6}  {:<8}  description",
        "name",
        "risk",
        "effects",
        width = max_name
    );
    println!("{}  ------  --------  -----------", "-".repeat(max_name));
    for op in &resp.operations {
        println!(
            "{:<width$}  {:<6}  {:<8}  {}",
            op.name,
            op.risk_level.as_str(),
            render_side_effects(op),
            first_line(op.description.as_deref().unwrap_or("")),
            width = max_name,
        );
    }
    if let Some(cursor) = resp.next_cursor.as_deref() {
        println!("\nnext_cursor: {cursor}");
    }
}

pub fn print_type(resp: &TypesResponse) {
    println!("name: {}", resp.name);
    if !resp.references.is_empty() {
        println!("references: {}", resp.references.join(", "));
    }
    println!("json_schema:");
    match serde_json::to_string_pretty(&resp.json_schema) {
        Ok(s) => {
            for line in s.lines() {
                println!("  {line}");
            }
        }
        Err(e) => println!("  <failed to pretty-print: {e}>"),
    }
}

fn render_side_effects(op: &OperationDescriptor) -> String {
    match op.side_effects {
        Some(true) => "yes".to_owned(),
        Some(false) => "no".to_owned(),
        None => "?".to_owned(),
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
