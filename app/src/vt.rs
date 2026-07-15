//! VirusTotal hash-reputation lookups (v3 API) — opt-in and **by-hash only**.
//!
//! Looks up a file's SHA-256 to show the detection ratio and threat label
//! WITHOUT ever uploading the sample. Lookups run on a background thread and are
//! cached by hash. The API key is read from `~/.hexed_vt_key` (or `$VT_API_KEY`)
//! and never leaves the machine except as the `x-apikey` header to VirusTotal.
//! Nothing happens unless the user turns enrichment on — even a by-hash lookup
//! tells VT (and anyone watching it) that the sample is being analyzed.

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

/// The reputation summary for one file hash.
#[derive(Clone, Debug, Default)]
pub struct VtVerdict {
    pub malicious: u32,
    pub suspicious: u32,
    /// Total engines that produced a result (denominator of the ratio).
    pub total: u32,
    /// VT's popular_threat_classification suggested label (family), if any.
    pub label: Option<String>,
    /// First-submission date (YYYY-MM-DD UTC), if known.
    pub first_seen: Option<String>,
    /// VT's perceptual icon hash (`main_icon_dhash`) — files sharing it usually
    /// share an icon (same lure/family). Used to pivot on the icon.
    pub icon_dhash: Option<String>,
    /// The hash isn't in VirusTotal at all (404).
    pub not_found: bool,
    /// A lookup error (bad key, rate limit, network).
    pub error: Option<String>,
}

pub struct Vt {
    /// User toggle: when off, no network lookups happen at all.
    pub enabled: bool,
    key: Option<String>,
    cache: HashMap<String, VtVerdict>,
    inflight: Option<(String, Receiver<VtVerdict>)>,
    queue: VecDeque<String>,
    icon_cache: HashMap<String, IconMatches>,
    icon_inflight: Option<(String, Receiver<IconMatches>)>,
}

impl Vt {
    pub fn new(enabled: bool) -> Self {
        Vt {
            enabled,
            key: load_key(),
            cache: HashMap::new(),
            inflight: None,
            queue: VecDeque::new(),
            icon_cache: HashMap::new(),
            icon_inflight: None,
        }
    }

    /// Whether an API key is configured (enrichment is useless without one).
    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Queue a lookup for `hash`. No-op if disabled, keyless, already cached,
    /// already queued/in-flight, or not a SHA-256.
    pub fn request(&mut self, hash: &str) {
        if !self.enabled || self.key.is_none() {
            return;
        }
        let h = hash.trim().to_lowercase();
        if h.len() != 64
            || self.cache.contains_key(&h)
            || self.queue.contains(&h)
            || self.inflight.as_ref().is_some_and(|(ih, _)| *ih == h)
        {
            return;
        }
        self.queue.push_back(h);
        self.pump();
    }

    fn pump(&mut self) {
        if self.inflight.is_some() {
            return;
        }
        let (Some(h), Some(key)) = (self.queue.pop_front(), self.key.clone()) else {
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let hh = h.clone();
        std::thread::spawn(move || {
            let _ = tx.send(lookup(&key, &hh));
        });
        self.inflight = Some((h, rx));
    }

    /// Drain finished lookups (file + icon); returns true if anything arrived.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        if let Some((h, rx)) = &self.inflight {
            match rx.try_recv() {
                Ok(v) => {
                    let h = h.clone();
                    self.cache.insert(h, v);
                    self.inflight = None;
                    self.pump();
                    changed = true;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.inflight = None;
                    self.pump();
                    changed = true;
                }
            }
        }
        if let Some((d, rx)) = &self.icon_inflight {
            match rx.try_recv() {
                Ok(m) => {
                    let d = d.clone();
                    self.icon_cache.insert(d, m);
                    self.icon_inflight = None;
                    changed = true;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.icon_inflight = None;
                    changed = true;
                }
            }
        }
        changed
    }

    /// Kick off an Intelligence search for how many files share `dhash` (one at
    /// a time; no-op if keyless, cached, or already in flight).
    pub fn request_icon(&mut self, dhash: &str) {
        // Mirror request(): never touch the network unless enrichment is
        // explicitly enabled. An icon Intelligence search discloses to VT that
        // we're analysing this sample, so the opt-in gate must apply here too.
        if !self.enabled {
            return;
        }
        let Some(key) = self.key.clone() else { return };
        let d = dhash.trim().to_string();
        if d.is_empty() || self.icon_cache.contains_key(&d) || self.icon_inflight.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let dd = d.clone();
        std::thread::spawn(move || {
            let _ = tx.send(icon_search(&key, &dd));
        });
        self.icon_inflight = Some((d, rx));
    }

    pub fn icon(&self, dhash: &str) -> Option<&IconMatches> {
        self.icon_cache.get(dhash.trim())
    }

    pub fn icon_pending(&self, dhash: &str) -> bool {
        self.icon_inflight.as_ref().is_some_and(|(d, _)| d == dhash.trim())
    }

    pub fn get(&self, hash: &str) -> Option<&VtVerdict> {
        self.cache.get(&hash.trim().to_lowercase())
    }

    pub fn is_pending(&self, hash: &str) -> bool {
        let h = hash.trim().to_lowercase();
        self.queue.contains(&h) || self.inflight.as_ref().is_some_and(|(ih, _)| *ih == h)
    }
}

/// Load the API key from `~/.hexed_vt_key`, falling back to `$VT_API_KEY`.
fn load_key() -> Option<String> {
    if let Some(home) = std::env::var_os("HOME") {
        let p = std::path::PathBuf::from(home).join(".hexed_vt_key");
        if let Ok(s) = std::fs::read_to_string(&p) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    std::env::var("VT_API_KEY").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// One blocking VT v3 file lookup (runs on a worker thread).
fn lookup(key: &str, hash: &str) -> VtVerdict {
    let url = format!("https://www.virustotal.com/api/v3/files/{hash}");
    let req = ureq::get(&url).set("x-apikey", key).timeout(Duration::from_secs(20));
    match req.call() {
        Ok(resp) => parse(resp),
        Err(ureq::Error::Status(404, _)) => VtVerdict { not_found: true, ..Default::default() },
        Err(ureq::Error::Status(401, _)) => err("invalid VT API key"),
        Err(ureq::Error::Status(429, _)) => err("VT rate limit — try again shortly"),
        Err(ureq::Error::Status(code, _)) => err(&format!("VT error {code}")),
        Err(e) => err(&format!("VT: {e}")),
    }
}

fn err(msg: &str) -> VtVerdict {
    VtVerdict { error: Some(msg.to_string()), ..Default::default() }
}

fn parse(resp: ureq::Response) -> VtVerdict {
    let json: serde_json::Value = match resp.into_json() {
        Ok(j) => j,
        Err(e) => return err(&format!("VT parse: {e}")),
    };
    let attr = &json["data"]["attributes"];
    let stats = &attr["last_analysis_stats"];
    let g = |k: &str| stats[k].as_u64().unwrap_or(0) as u32;
    let malicious = g("malicious");
    let suspicious = g("suspicious");
    let harmless = g("harmless");
    let undetected = g("undetected");
    // Saturating: a hostile/malformed VT response could set these near u32::MAX
    // and overflow-panic (debug) / wrap to a tiny total (release), skewing the
    // detection ratio.
    let total = malicious
        .saturating_add(suspicious)
        .saturating_add(harmless)
        .saturating_add(undetected)
        .saturating_add(g("timeout"))
        .saturating_add(g("type-unsupported"))
        .saturating_add(g("failure"))
        .saturating_add(g("confirmed-timeout"));
    let label = attr["popular_threat_classification"]["suggested_threat_label"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let first_seen = attr["first_submission_date"]
        .as_i64()
        .map(hexed_core::ymd_utc);
    let icon_dhash = attr["main_icon_dhash"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    VtVerdict {
        malicious,
        suspicious,
        total,
        label,
        first_seen,
        icon_dhash,
        not_found: false,
        error: None,
    }
}

/// How many files on VirusTotal share an icon (by `main_icon_dhash`).
#[derive(Clone, Debug)]
pub struct IconMatches {
    /// Total matching files (`meta.total_hits`). 1 = the icon looks unique.
    pub count: u32,
    pub error: Option<String>,
}

/// Intelligence search for files sharing `dhash`. Requires a VT key with
/// Intelligence access; returns an error verdict otherwise.
fn icon_search(key: &str, dhash: &str) -> IconMatches {
    let url = format!(
        "https://www.virustotal.com/api/v3/intelligence/search?query=main_icon_dhash:{dhash}&limit=1"
    );
    match ureq::get(&url).set("x-apikey", key).timeout(Duration::from_secs(25)).call() {
        Ok(resp) => {
            let j: serde_json::Value = resp.into_json().unwrap_or_default();
            // total across all pages; fall back to this page's count.
            let count = j["meta"]["total_hits"]
                .as_u64()
                .or_else(|| j["meta"]["count"].as_u64())
                .unwrap_or_else(|| j["data"].as_array().map(|a| a.len() as u64).unwrap_or(0));
            IconMatches { count: count as u32, error: None }
        }
        Err(ureq::Error::Status(403, _)) => IconMatches {
            count: 0,
            error: Some("no VT Intelligence access".into()),
        },
        Err(ureq::Error::Status(429, _)) => IconMatches {
            count: 0,
            error: Some("VT rate limit".into()),
        },
        Err(e) => IconMatches { count: 0, error: Some(format!("VT: {e}")) },
    }
}
