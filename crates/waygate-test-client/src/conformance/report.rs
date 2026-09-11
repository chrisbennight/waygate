//! Conformance report: a list of named checks with status + latency +
//! optional detail. Renders either as a checklist or as JSON (for CI).

use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Copy, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    Skip,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub latency_ms: u128,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pass(&mut self, name: impl Into<String>, latency: Duration) {
        self.checks.push(Check {
            name: name.into(),
            status: Status::Pass,
            detail: None,
            latency_ms: latency.as_millis(),
        });
    }

    pub fn fail(&mut self, name: impl Into<String>, latency: Duration, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status: Status::Fail,
            detail: Some(detail.into()),
            latency_ms: latency.as_millis(),
        });
    }

    pub fn skip(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status: Status::Skip,
            detail: Some(detail.into()),
            latency_ms: 0,
        });
    }

    pub fn overall(&self) -> Status {
        if self.checks.iter().any(|c| c.status == Status::Fail) {
            Status::Fail
        } else if self.checks.iter().all(|c| c.status == Status::Skip) {
            Status::Skip
        } else {
            Status::Pass
        }
    }

    pub fn print(&self, json: bool) {
        if json {
            if let Ok(s) = serde_json::to_string_pretty(self) {
                println!("{s}");
            }
            return;
        }

        let name_w = self
            .checks
            .iter()
            .map(|c| c.name.len())
            .max()
            .unwrap_or(4)
            .max(4);
        println!("{:<width$}  status  ms    detail", "name", width = name_w);
        println!("{}  ------  ----  ------", "-".repeat(name_w),);
        for c in &self.checks {
            let detail = c.detail.as_deref().unwrap_or("");
            println!(
                "{:<width$}  {:<6}  {:<4}  {}",
                c.name,
                c.status.as_str(),
                c.latency_ms,
                detail,
                width = name_w,
            );
        }
        let pass = self
            .checks
            .iter()
            .filter(|c| c.status == Status::Pass)
            .count();
        let fail = self
            .checks
            .iter()
            .filter(|c| c.status == Status::Fail)
            .count();
        let skip = self
            .checks
            .iter()
            .filter(|c| c.status == Status::Skip)
            .count();
        println!();
        println!(
            "overall: {}  ({pass} pass / {fail} fail / {skip} skip)",
            self.overall().as_str(),
        );
    }
}
