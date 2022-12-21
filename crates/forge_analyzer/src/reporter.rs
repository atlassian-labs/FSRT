

use serde::Serialize;
use time::{Date, OffsetDateTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

// TODO: Can probably use [`Rc`] instead of [`String`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Vulnerability {
    pub(crate) check_name: String,
    pub(crate) description: String,
    pub(crate) recommendation: &'static str,
    pub(crate) proof: String,
    pub(crate) severity: Severity,
    pub(crate) app_key: String,
    pub(crate) app_name: String,
    pub(crate) date: Date,
}

pub trait IntoVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    vulns: Vec<Vulnerability>,
    scanner: &'static str,
    #[serde(with = "time::serde::iso8601")]
    started_at: OffsetDateTime,
    #[serde(with = "time::serde::iso8601")]
    ended_at: OffsetDateTime,
    scanned: Vec<String>,
    errors: bool,
}

pub struct Reporter {
    vulns: Vec<Vulnerability>,
    started_at: OffsetDateTime,
    // (key, name)
    apps: Vec<(String, String)>,
    current_app: usize,
}

impl Reporter {
    #[inline]
    pub fn new() -> Self {
        Self {
            vulns: Vec::new(),
            started_at: OffsetDateTime::now_utc(),
            apps: Vec::new(),
            current_app: 0,
        }
    }

    #[inline]
    pub fn add_app(&mut self, key: String, name: String) {
        self.apps.push((key, name));
        self.current_app = self.apps.len() - 1;
    }

    #[inline]
    pub fn app_name(&self) -> &str {
        &self.apps[self.current_app].1
    }

    #[inline]
    pub fn app_key(&self) -> &str {
        &self.apps[self.current_app].0
    }

    #[inline]
    pub fn current_date(&self) -> Date {
        self.started_at.date()
    }

    pub fn add_vulnerabilities(&mut self, vuln_reports: impl IntoIterator<Item = impl IntoVuln>) {
        let vuln_reports = vuln_reports.into_iter();
        self.vulns.reserve(vuln_reports.size_hint().0);
        for vuln in vuln_reports {
            self.vulns.push(vuln.into_vuln(self));
        }
    }

    #[inline]
    pub fn into_report(self) -> Report {
        Report {
            vulns: self.vulns,
            scanner: "FSRT",
            started_at: self.started_at,
            ended_at: OffsetDateTime::now_utc(),
            scanned: self.apps.into_iter().map(|(key, _)| key).collect(),
            errors: false,
        }
    }
}

impl Default for Reporter {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
