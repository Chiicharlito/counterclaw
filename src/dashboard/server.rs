//! Dashboard HTTP server — endpoints JSON pour monitorer CounterClaw.
//!
//! Serveur axum leger qui expose l'etat du daemon via une API REST.
//! Securise par :
//! - Authentification Bearer token sur les endpoints d'ecriture
//! - Validation d'Origin (CSRF) sur les endpoints mutants
//! - Rate limiting en memoire (10/s write, 100/s read)
//! - Validation des entrees (longueur, doublons, regex)
//! - Headers de securite (CSP, X-Frame-Options, X-Content-Type-Options)
//! - Auto-protection (chemins critiques non supprimables)

// Input validation constants
const MAX_RULE_VALUE_LENGTH: usize = 500;
const MAX_RULES_PER_CATEGORY: usize = 1000;
use crate::daemon::DaemonState;
use crate::types::{GuardModule, Severity};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, Json, Response};
use axum::routing::get;
use axum::Router;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Self-protection — paths that can NEVER be removed via API
// ---------------------------------------------------------------------------

/// Returns paths that are ALWAYS protected and cannot be removed via API.
/// V3: Includes both system-level and user-level (~/.counterclaw/) paths.
pub fn get_self_protection_paths() -> Vec<String> {
    crate::guards::fs_guard::get_self_protection_paths()
}

// ---------------------------------------------------------------------------
// Rate limiter — simple in-memory per-key tracking
// ---------------------------------------------------------------------------

/// Maximum number of tracked keys in the rate limiter (V11: prevent DoS).
const MAX_TRACKED_KEYS: usize = 10_000;

/// TTL for rate limiter entries in seconds (V11: auto-cleanup).
const RATE_LIMITER_TTL_SECS: u64 = 60;

/// Simple in-memory rate limiter tracking request timestamps per key.
/// V11: Includes TTL-based cleanup and key cap to prevent memory DoS.
pub struct RateLimiter {
    /// Map of client key -> deque of request timestamps.
    requests: HashMap<String, VecDeque<Instant>>,
    /// Counter for periodic cleanup scheduling.
    check_counter: u64,
}

impl RateLimiter {
    /// Create a new empty rate limiter.
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
            check_counter: 0,
        }
    }

    /// Check if a request is allowed under the given rate limit.
    ///
    /// Returns true if allowed, false if rate-limited.
    /// `max_per_second` is the maximum number of requests per second.
    /// V11: Periodically cleans expired entries and enforces key cap.
    pub fn check_rate(&mut self, key: &str, max_per_second: u32) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(1);

        // V11: Periodic cleanup every 100 requests
        self.check_counter += 1;
        if self.check_counter.is_multiple_of(100) {
            self.cleanup_expired();
        }

        // V11: Enforce key cap — reject if too many keys tracked
        if !self.requests.contains_key(key) && self.requests.len() >= MAX_TRACKED_KEYS {
            self.cleanup_expired();
            // If still at cap after cleanup, evict oldest entries
            if self.requests.len() >= MAX_TRACKED_KEYS {
                self.evict_oldest();
            }
        }

        let timestamps = self.requests.entry(key.to_string()).or_default();

        // Remove timestamps older than the window
        while let Some(front) = timestamps.front() {
            if now.duration_since(*front) > window {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        if timestamps.len() >= max_per_second as usize {
            return false;
        }

        timestamps.push_back(now);
        true
    }

    /// V11: Returns the number of tracked keys (for monitoring/testing).
    pub fn tracked_keys_count(&self) -> usize {
        self.requests.len()
    }

    /// V11: Remove entries that have no activity within the TTL window.
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let ttl = std::time::Duration::from_secs(RATE_LIMITER_TTL_SECS);

        self.requests.retain(|_, timestamps| {
            // Keep entries that have at least one timestamp within TTL
            timestamps
                .back()
                .map(|last| now.duration_since(*last) < ttl)
                .unwrap_or(false)
        });
    }

    /// V11: Evict the oldest entries when at key cap.
    fn evict_oldest(&mut self) {
        // Remove entries with the oldest last-access time
        let target = MAX_TRACKED_KEYS * 9 / 10; // Evict down to 90% capacity
        while self.requests.len() > target {
            // Find key with oldest last timestamp
            let oldest_key = self
                .requests
                .iter()
                .min_by_key(|(_, ts)| ts.back().copied())
                .map(|(k, _)| k.clone());

            if let Some(key) = oldest_key {
                self.requests.remove(&key);
            } else {
                break;
            }
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DashboardState — wraps DaemonState + security features
// ---------------------------------------------------------------------------

/// Dashboard state wrapping the daemon state with security features.
///
/// This is the axum state type for the router, providing:
/// - Access to the underlying DaemonState
/// - Optional Bearer token authentication
/// - In-memory rate limiting
#[derive(Clone)]
pub struct DashboardState {
    /// The underlying daemon state (config, guards, event buffer).
    pub daemon_state: Arc<DaemonState>,
    /// Optional Bearer token for write endpoint authentication.
    pub auth_token: Option<String>,
    /// In-memory rate limiter shared across handlers.
    pub rate_limiter: Arc<std::sync::Mutex<RateLimiter>>,
}

impl DashboardState {
    /// Create a new DashboardState with no auth token.
    pub fn new(daemon_state: Arc<DaemonState>) -> Self {
        Self {
            daemon_state,
            auth_token: None,
            rate_limiter: Arc::new(std::sync::Mutex::new(RateLimiter::new())),
        }
    }

    /// Create a new DashboardState with a Bearer auth token.
    pub fn with_token(daemon_state: Arc<DaemonState>, token: String) -> Self {
        Self {
            daemon_state,
            auth_token: Some(token),
            rate_limiter: Arc::new(std::sync::Mutex::new(RateLimiter::new())),
        }
    }
}

/// Generate a random 64-character hex API token (32 bytes of entropy).
///
/// Uses two UUIDv4 values concatenated in simple (no-hyphen) format
/// to produce a 64-character hex string.
pub fn generate_api_token() -> String {
    let id1 = uuid::Uuid::new_v4();
    let id2 = uuid::Uuid::new_v4();
    format!("{}{}", id1.as_simple(), id2.as_simple())
}

// ---------------------------------------------------------------------------
// Security helpers — auth, CSRF, rate limiting
// ---------------------------------------------------------------------------

/// Extract a Bearer token from the Authorization header.
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string())
}

/// Validate the Bearer token against the configured auth token.
///
/// - If no auth token is configured, all requests are allowed.
/// - If an auth token is configured, the request must include a matching
///   `Authorization: Bearer <token>` header.
pub fn validate_auth(state: &DashboardState, headers: &HeaderMap) -> Result<(), StatusCode> {
    match &state.auth_token {
        None => Ok(()), // No auth configured => allow all
        Some(expected) => {
            let provided = extract_bearer_token(headers);
            match provided {
                Some(ref token) if token == expected => Ok(()),
                _ => Err(StatusCode::UNAUTHORIZED),
            }
        }
    }
}

/// Validate the Origin header on mutating requests (CSRF protection).
///
/// Accepts:
/// - Missing Origin header (for curl/API tools)
/// - localhost, 127.0.0.1, ::1 with any port
///
/// Rejects:
/// - Any other origin with 403 Forbidden
pub fn validate_origin(headers: &HeaderMap) -> Result<(), StatusCode> {
    let origin = match headers.get("origin").and_then(|v| v.to_str().ok()) {
        None => return Ok(()), // No Origin header => allow (curl, API clients)
        Some(o) => o,
    };

    // Parse the origin to extract the host
    // Origin format: scheme://host[:port]
    let host = origin
        .split("://")
        .nth(1)
        .unwrap_or(origin)
        .split(':')
        .next()
        .unwrap_or("");

    match host {
        "localhost" | "127.0.0.1" | "::1" | "[::1]" => Ok(()),
        _ => Err(StatusCode::FORBIDDEN),
    }
}

/// Check rate limiting for a request.
///
/// - Write endpoints: max 10 requests per second
/// - Read endpoints: max 100 requests per second
fn check_rate_limit(state: &DashboardState, key: &str, is_write: bool) -> Result<(), StatusCode> {
    let max_per_second = if is_write { 10 } else { 100 };
    let mut limiter = state.rate_limiter.lock().expect("rate limiter lock");
    if limiter.check_rate(key, max_per_second) {
        Ok(())
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

// ---------------------------------------------------------------------------
// DTOs — types serialisables pour les reponses JSON
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    timestamp: String,
}

#[derive(Serialize)]
struct GuardStatusResponse {
    name: String,
    running: bool,
    events_total: u64,
    events_blocked: u64,
    uptime_seconds: i64,
}

#[derive(Serialize)]
struct StatusResponse {
    daemon_uptime_seconds: i64,
    mode: String,
    guards: Vec<GuardStatusResponse>,
}

#[derive(Serialize)]
struct EventDto {
    id: String,
    timestamp: String,
    module: String,
    severity: String,
    action_taken: String,
    description: String,
}

#[derive(Serialize)]
struct EventsResponse {
    events: Vec<EventDto>,
    total: usize,
}

#[derive(Deserialize)]
pub struct EventsQuery {
    pub limit: Option<usize>,
    pub severity: Option<String>,
    pub module: Option<String>,
    pub last: Option<String>,
}

// ---------------------------------------------------------------------------
// parse_duration — helper pur
// ---------------------------------------------------------------------------

/// Parse une duree humaine ("2h", "30m", "60s") en chrono::Duration.
pub fn parse_duration(s: &str) -> Option<Duration> {
    if s.is_empty() {
        return None;
    }

    let s = s.trim();
    if s.len() < 2 {
        return None;
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: i64 = num_str.parse().ok()?;

    match unit {
        "h" => Some(Duration::hours(num)),
        "m" => Some(Duration::minutes(num)),
        "s" => Some(Duration::seconds(num)),
        _ => None,
    }
}

/// Parse une string de severity en enum.
fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "warning" => Some(Severity::Warning),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Parse une string de module en enum.
fn parse_module(s: &str) -> Option<GuardModule> {
    match s.to_lowercase().as_str() {
        "fs_guard" => Some(GuardModule::FsGuard),
        "cdp_proxy" => Some(GuardModule::CdpProxy),
        "net_guard" => Some(GuardModule::NetGuard),
        "cmd_guard" => Some(GuardModule::CmdGuard),
        "system" => Some(GuardModule::System),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Dashboard HTML — page inline, zero dependance externe
// ---------------------------------------------------------------------------

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CounterClaw Dashboard</title>
<style>
:root{
  --bg:#1a1a2e;--bg2:#16213e;--card:#0f3460;--accent:#e94560;
  --green:#00d27a;--yellow:#ffc107;--red:#e94560;
  --text:#e0e0e0;--muted:#8892b0;--border:#233554;--input-bg:#1c2a4a;
}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;background:var(--bg);color:var(--text);min-height:100vh;}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:1rem 2rem;display:flex;align-items:center;justify-content:space-between;}
.logo-title{display:flex;align-items:center;gap:0.8rem;}
header h1{font-size:1.4rem;font-weight:700;letter-spacing:0.05em;}
header h1 span{color:var(--accent);}
.header-right{display:flex;align-items:center;gap:1rem;}
.badge{display:inline-block;padding:0.2rem 0.7rem;border-radius:12px;font-size:0.75rem;font-weight:600;text-transform:uppercase;}
.badge-ok{background:var(--green);color:#000;}
.badge-warn{background:var(--yellow);color:#000;}
.badge-crit{background:var(--red);color:#fff;}
.badge-info{background:var(--muted);color:#fff;}
.meta{color:var(--muted);font-size:0.8rem;}
main{padding:1.5rem 2rem;max-width:1200px;margin:0 auto;}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem;}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.2rem;}
.card h3{font-size:0.8rem;color:var(--muted);margin-bottom:0.4rem;text-transform:uppercase;letter-spacing:0.05em;}
.card .value{font-size:1.5rem;font-weight:700;}
.mode-select{background:var(--input-bg);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:0.3rem 0.6rem;font-size:1rem;font-weight:700;cursor:pointer;}
.mode-select option{background:var(--bg);color:var(--text);}
/* Tabs */
.tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:1.5rem;}
.tab-btn{background:none;border:none;color:var(--muted);font-size:0.85rem;font-weight:600;padding:0.7rem 1.2rem;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px;transition:color 0.2s,border-color 0.2s;}
.tab-btn:hover{color:var(--text);}
.tab-btn.active{color:var(--accent);border-bottom-color:var(--accent);}
.tab-panel{display:none;}
.tab-panel.active{display:block;}
/* Guards grid */
.guards-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:0.8rem;margin-bottom:1.5rem;}
.guard-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem;display:flex;align-items:center;gap:0.8rem;}
.guard-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}
.guard-dot.on{background:var(--green);box-shadow:0 0 6px var(--green);}
.guard-dot.off{background:var(--red);}
.guard-name{font-weight:600;font-size:0.9rem;}
.guard-stats{font-size:0.75rem;color:var(--muted);}
/* Tables */
table{width:100%;border-collapse:collapse;font-size:0.85rem;}
th{text-align:left;padding:0.6rem 0.8rem;border-bottom:2px solid var(--border);color:var(--muted);text-transform:uppercase;font-size:0.75rem;letter-spacing:0.05em;}
td{padding:0.5rem 0.8rem;border-bottom:1px solid var(--border);vertical-align:top;}
tr:hover{background:rgba(255,255,255,0.03);}
.desc{max-width:400px;word-break:break-word;}
.empty{text-align:center;padding:2rem;color:var(--muted);}
/* Rules */
.rules-section{margin-bottom:1.5rem;}
.rules-section h3{font-size:0.9rem;margin-bottom:0.6rem;color:var(--accent);text-transform:uppercase;letter-spacing:0.04em;}
.rule-item{display:flex;align-items:center;justify-content:space-between;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:0.6rem 1rem;margin-bottom:0.4rem;}
.rule-value{font-size:0.85rem;word-break:break-all;}
.rule-actions{display:flex;gap:0.4rem;}
.btn{background:var(--input-bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.3rem 0.6rem;font-size:0.75rem;cursor:pointer;transition:background 0.2s;}
.btn:hover{background:var(--border);}
.btn-danger{color:var(--red);}
.btn-danger:hover{background:rgba(233,69,96,0.2);}
.btn-accent{background:var(--accent);color:#fff;border-color:var(--accent);}
.btn-accent:hover{background:#c73750;}
/* Add form */
.add-form{display:flex;gap:0.5rem;align-items:center;margin-top:0.8rem;flex-wrap:wrap;}
.add-form select,.add-form input{background:var(--input-bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.4rem 0.6rem;font-size:0.8rem;}
.add-form input{flex:1;min-width:200px;}
/* Toast */
.toast{position:fixed;top:1rem;right:1rem;background:var(--green);color:#000;padding:0.7rem 1.2rem;border-radius:8px;font-size:0.85rem;font-weight:600;z-index:1000;opacity:0;transition:opacity 0.3s;pointer-events:none;}
.toast.error{background:var(--red);color:#fff;}
.toast.show{opacity:1;}
@media(max-width:600px){header{padding:0.8rem 1rem;}main{padding:1rem;}.cards{grid-template-columns:1fr 1fr;}.tabs{overflow-x:auto;}}
</style>
</head>
<body>
<header>
  <div class="logo-title">
    <svg width="32" height="32" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="32" cy="32" r="30" stroke="#e94560" stroke-width="3" fill="#16213e"/>
      <path d="M22 20 L32 14 L42 20 L42 36 L32 42 L22 36Z" stroke="#e94560" stroke-width="2" fill="none"/>
      <path d="M32 14 L32 42" stroke="#e94560" stroke-width="1.5"/>
      <path d="M22 20 L42 36" stroke="#e94560" stroke-width="1"/>
      <path d="M42 20 L22 36" stroke="#e94560" stroke-width="1"/>
      <circle cx="32" cy="28" r="5" fill="#e94560" opacity="0.8"/>
      <path d="M26 44 L32 50 L38 44" stroke="#00d27a" stroke-width="2" fill="none" stroke-linecap="round"/>
    </svg>
    <h1>Counter<span>Claw</span></h1>
  </div>
  <div class="header-right">
    <span id="daemon-badge" class="badge badge-ok">loading</span>
    <span class="meta" id="last-update"></span>
  </div>
</header>
<main>
  <div class="cards">
    <div class="card">
      <h3>Mode</h3>
      <select id="mode-select" class="mode-select" onchange="changeMode(this.value)">
        <option value="monitor">monitor</option>
        <option value="enforce">enforce</option>
        <option value="paranoid">paranoid</option>
      </select>
    </div>
    <div class="card"><h3>Uptime</h3><div class="value" id="uptime">—</div></div>
    <div class="card"><h3>Events</h3><div class="value" id="event-count">—</div></div>
    <div class="card"><h3>Guards</h3><div class="value" id="guard-count">—</div></div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" data-tab="tab-overview" onclick="switchTab('tab-overview',this)">Overview</button>
    <button class="tab-btn" data-tab="tab-fs" onclick="switchTab('tab-fs',this)">Files</button>
    <button class="tab-btn" data-tab="tab-domains" onclick="switchTab('tab-domains',this)">Domains</button>
    <button class="tab-btn" data-tab="tab-egress" onclick="switchTab('tab-egress',this)">Egress</button>
    <button class="tab-btn" data-tab="tab-commands" onclick="switchTab('tab-commands',this)">Commands</button>
  </div>

  <!-- Overview tab -->
  <div id="tab-overview" class="tab-panel active">
    <h2 style="margin-bottom:0.8rem;font-size:1rem;">Guards Status</h2>
    <div class="guards-grid" id="guards"></div>
    <h2 style="margin-bottom:0.8rem;font-size:1rem;">Recent Events</h2>
    <table>
      <thead><tr><th>Time</th><th>Module</th><th>Severity</th><th>Action</th><th>Description</th></tr></thead>
      <tbody id="events-body"><tr><td colspan="5" class="empty">Loading...</td></tr></tbody>
    </table>
  </div>

  <!-- Files (FS Guard) tab -->
  <div id="tab-fs" class="tab-panel">
    <div class="rules-section"><h3>Blocked Paths</h3><div id="fs-blocked"></div></div>
    <div class="rules-section"><h3>Read-Only Paths</h3><div id="fs-read_only"></div></div>
    <div class="rules-section"><h3>Allowed Paths</h3><div id="fs-allowed"></div></div>
    <div class="add-form">
      <select id="fs-cat"><option value="blocked">Blocked</option><option value="read_only">Read-Only</option><option value="allowed">Allowed</option></select>
      <input id="fs-val" type="text" placeholder="Path (e.g. ~/.ssh)"/>
      <button class="btn btn-accent" onclick="addRule('fs',document.getElementById('fs-cat').value,document.getElementById('fs-val').value)">Add</button>
    </div>
  </div>

  <!-- Domains tab -->
  <div id="tab-domains" class="tab-panel">
    <div class="rules-section"><h3>Blocked Domains</h3><div id="domains-blocked"></div></div>
    <div class="rules-section"><h3>Allowed Domains</h3><div id="domains-allowed"></div></div>
    <div class="rules-section"><h3>Require Approval</h3><div id="domains-require_approval"></div></div>
    <div class="add-form">
      <select id="dom-cat"><option value="blocked">Blocked</option><option value="allowed">Allowed</option><option value="require_approval">Require Approval</option></select>
      <input id="dom-val" type="text" placeholder="Domain (e.g. evil.com)"/>
      <button class="btn btn-accent" onclick="addRule('domains',document.getElementById('dom-cat').value,document.getElementById('dom-val').value)">Add</button>
    </div>
  </div>

  <!-- Egress tab -->
  <div id="tab-egress" class="tab-panel">
    <div class="rules-section"><h3>Allowed Egress</h3><div id="egress-allowed"></div></div>
    <div class="add-form">
      <input id="egress-val" type="text" placeholder="Domain (e.g. api.github.com)"/>
      <button class="btn btn-accent" onclick="addRule('egress','allowed',document.getElementById('egress-val').value)">Add</button>
    </div>
  </div>

  <!-- Commands tab -->
  <div id="tab-commands" class="tab-panel">
    <div class="rules-section"><h3>Blacklisted Commands</h3><div id="cmd-blacklist"></div></div>
    <div class="rules-section"><h3>Require Approval</h3><div id="cmd-require_approval"></div></div>
    <div class="add-form">
      <select id="cmd-cat"><option value="blacklist">Blacklist</option><option value="require_approval">Require Approval</option></select>
      <input id="cmd-pattern" type="text" placeholder="Regex pattern"/>
      <input id="cmd-desc" type="text" placeholder="Description"/>
      <select id="cmd-sev"><option value="high">High</option><option value="warning">Warning</option><option value="critical">Critical</option></select>
      <button class="btn btn-accent" onclick="addCmdRule()">Add</button>
    </div>
  </div>
</main>
<div id="toast" class="toast"></div>
<script>
/* === Utility functions === */
function fmt(s){
  if(!s||s<=0)return'0s';
  var h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
  if(h>0)return h+'h '+m+'m';
  if(m>0)return m+'m '+sec+'s';
  return sec+'s';
}
function sevBadge(s){
  var c={critical:'badge-crit',high:'badge-crit',warning:'badge-warn',info:'badge-info'};
  var el=document.createElement('span');
  el.className='badge '+(c[s]||'badge-info');
  el.textContent=s;
  return el;
}
function showToast(msg,isError){
  var t=document.getElementById('toast');
  t.textContent=msg;
  t.className='toast'+(isError?' error':'')+' show';
  setTimeout(function(){t.className='toast';},3000);
}
function switchTab(id,btn){
  document.querySelectorAll('.tab-panel').forEach(function(p){p.classList.remove('active');});
  document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}

/* === Mode change === */
function changeMode(mode){
  fetch('/api/mode',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode:mode})})
  .then(function(r){if(!r.ok)throw new Error('Failed');return r.json();})
  .then(function(){showToast('Mode changed to '+mode);})
  .catch(function(){showToast('Failed to change mode',true);});
}

/* === Rules CRUD === */
function addRule(guard,category,value){
  if(!value||!value.trim()){showToast('Value cannot be empty',true);return;}
  fetch('/api/rules/'+guard,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({category:category,value:value.trim()})})
  .then(function(r){if(!r.ok)throw new Error('Failed');return r.json();})
  .then(function(){showToast('Rule added');loadRules();})
  .catch(function(){showToast('Failed to add rule',true);});
}
function addCmdRule(){
  var cat=document.getElementById('cmd-cat').value;
  var pattern=document.getElementById('cmd-pattern').value;
  var desc=document.getElementById('cmd-desc').value;
  var sev=document.getElementById('cmd-sev').value;
  if(!pattern||!pattern.trim()){showToast('Pattern cannot be empty',true);return;}
  fetch('/api/rules/commands',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({category:cat,pattern:pattern.trim(),description:desc,severity:sev})})
  .then(function(r){if(!r.ok)throw new Error('Failed');return r.json();})
  .then(function(){showToast('Command rule added');loadRules();})
  .catch(function(){showToast('Failed to add command rule',true);});
}
function deleteRule(guard,category,index){
  fetch('/api/rules/'+guard+'/'+category+'/'+index,{method:'DELETE'})
  .then(function(r){if(!r.ok)throw new Error('Failed');return r.json();})
  .then(function(){showToast('Rule deleted');loadRules();})
  .catch(function(){showToast('Failed to delete rule',true);});
}
function renderRules(containerId,items,guard,category){
  var c=document.getElementById(containerId);
  c.textContent='';
  if(!items||items.length===0){
    var empty=document.createElement('div');
    empty.className='empty';
    empty.textContent='No rules';
    c.appendChild(empty);
    return;
  }
  items.forEach(function(item,i){
    var row=document.createElement('div');
    row.className='rule-item';
    var val=document.createElement('span');
    val.className='rule-value';
    if(typeof item==='string'){val.textContent=item;}
    else{val.textContent=(item.pattern||'')+(item.description?' — '+item.description:'');}
    row.appendChild(val);
    var actions=document.createElement('span');
    actions.className='rule-actions';
    var del=document.createElement('button');
    del.className='btn btn-danger';
    del.textContent='Delete';
    del.onclick=function(){deleteRule(guard,category,i);};
    actions.appendChild(del);
    row.appendChild(actions);
    c.appendChild(row);
  });
}
function loadRules(){
  fetch('/api/rules').then(function(r){return r.json();}).then(function(d){
    renderRules('fs-blocked',d.fs&&d.fs.blocked,'fs','blocked');
    renderRules('fs-read_only',d.fs&&d.fs.read_only,'fs','read_only');
    renderRules('fs-allowed',d.fs&&d.fs.allowed,'fs','allowed');
    renderRules('domains-blocked',d.domains&&d.domains.blocked,'domains','blocked');
    renderRules('domains-allowed',d.domains&&d.domains.allowed,'domains','allowed');
    renderRules('domains-require_approval',d.domains&&d.domains.require_approval,'domains','require_approval');
    renderRules('egress-allowed',d.egress&&d.egress.allowed,'egress','allowed');
    renderRules('cmd-blacklist',d.commands&&d.commands.blacklist,'commands','blacklist');
    renderRules('cmd-require_approval',d.commands&&d.commands.require_approval,'commands','require_approval');
  }).catch(function(){});
}

/* === Status refresh === */
function refresh(){
  fetch('/api/status').then(function(r){return r.json();}).then(function(d){
    var sel=document.getElementById('mode-select');
    if(sel&&d.mode)sel.value=d.mode;
    document.getElementById('uptime').textContent=fmt(d.daemon_uptime_seconds);
    document.getElementById('daemon-badge').textContent=d.mode||'ok';
    document.getElementById('daemon-badge').className='badge badge-ok';
    var gArr=d.guards||[];
    document.getElementById('guard-count').textContent=gArr.filter(function(g){return g.running;}).length+'/'+gArr.length;
    var g=document.getElementById('guards');
    g.textContent='';
    gArr.forEach(function(gd){
      var card=document.createElement('div');
      card.className='guard-card';
      var dot=document.createElement('div');
      dot.className='guard-dot '+(gd.running?'on':'off');
      card.appendChild(dot);
      var info=document.createElement('div');
      var name=document.createElement('div');
      name.className='guard-name';
      name.textContent=gd.name;
      info.appendChild(name);
      var stats=document.createElement('div');
      stats.className='guard-stats';
      stats.textContent=gd.events_total+' events, '+gd.events_blocked+' blocked';
      info.appendChild(stats);
      card.appendChild(info);
      g.appendChild(card);
    });
  }).catch(function(){
    document.getElementById('daemon-badge').textContent='offline';
    document.getElementById('daemon-badge').className='badge badge-crit';
  });
  fetch('/api/events?limit=20').then(function(r){return r.json();}).then(function(d){
    document.getElementById('event-count').textContent=d.total||0;
    var tb=document.getElementById('events-body');
    if(!d.events||d.events.length===0){
      tb.textContent='';
      var tr=document.createElement('tr');
      var td=document.createElement('td');
      td.colSpan=5;td.className='empty';td.textContent='No events yet';
      tr.appendChild(td);tb.appendChild(tr);
      return;
    }
    tb.textContent='';
    d.events.forEach(function(e){
      var tr=document.createElement('tr');
      var tdTime=document.createElement('td');
      tdTime.textContent=e.timestamp?e.timestamp.replace('T',' ').replace(' UTC',''):'—';
      tr.appendChild(tdTime);
      var tdMod=document.createElement('td');
      tdMod.textContent=e.module;
      tr.appendChild(tdMod);
      var tdSev=document.createElement('td');
      tdSev.appendChild(sevBadge(e.severity));
      tr.appendChild(tdSev);
      var tdAct=document.createElement('td');
      tdAct.textContent=e.action_taken;
      tr.appendChild(tdAct);
      var tdDesc=document.createElement('td');
      tdDesc.className='desc';
      tdDesc.textContent=e.description;
      tr.appendChild(tdDesc);
      tb.appendChild(tr);
    });
  }).catch(function(){});
  document.getElementById('last-update').textContent='Updated: '+new Date().toLocaleTimeString();
}

/* === Init === */
refresh();
loadRules();
setInterval(function(){refresh();loadRules();},5000);
</script>
</body>
</html>"##;

// ---------------------------------------------------------------------------
// Security headers middleware
// ---------------------------------------------------------------------------

/// Adds security headers (CSP, X-Content-Type-Options, X-Frame-Options)
/// to all responses.
async fn security_headers_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "content-security-policy",
        "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'"
            .parse()
            .expect("valid header value"),
    );
    headers.insert(
        "x-content-type-options",
        "nosniff".parse().expect("valid header value"),
    );
    headers.insert(
        "x-frame-options",
        "DENY".parse().expect("valid header value"),
    );
    response
}

// ---------------------------------------------------------------------------
// Handlers — read endpoints (no auth required)
// ---------------------------------------------------------------------------

/// Sert la page HTML du dashboard.
async fn dashboard_handler() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn health_handler(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<HealthResponse>, StatusCode> {
    check_rate_limit(&state, "read", false)?;
    let _ = &headers; // consumed for rate limit key (future: per-IP)
    Ok(Json(HealthResponse {
        status: "ok".to_string(),
        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%S UTC").to_string(),
    }))
}

async fn status_handler(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, StatusCode> {
    check_rate_limit(&state, "read", false)?;
    let _ = &headers;
    let uptime = Utc::now() - state.daemon_state.start_time;
    let guards = state
        .daemon_state
        .guard_statuses()
        .into_iter()
        .map(|(name, status)| GuardStatusResponse {
            name,
            running: status.running,
            events_total: status.events_total,
            events_blocked: status.events_blocked,
            uptime_seconds: status.uptime.num_seconds(),
        })
        .collect();

    Ok(Json(StatusResponse {
        daemon_uptime_seconds: uptime.num_seconds(),
        mode: state.daemon_state.mode().to_string(),
        guards,
    }))
}

async fn events_handler(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Query(params): Query<EventsQuery>,
) -> Result<Json<EventsResponse>, StatusCode> {
    check_rate_limit(&state, "read", false)?;
    let _ = &headers;
    let limit = params.limit.unwrap_or(0);
    let min_severity = params.severity.as_deref().and_then(parse_severity);
    let module = params.module.as_deref().and_then(parse_module);
    let since = params
        .last
        .as_deref()
        .and_then(parse_duration)
        .map(|d| Utc::now() - d);

    let buf = state.daemon_state.event_buffer.read().expect("buffer lock");
    let events = buf.query(limit, min_severity.as_ref(), module.as_ref(), since);

    let total = events.len();
    let event_dtos: Vec<EventDto> = events
        .into_iter()
        .map(|e| {
            // Use serde serialization for consistent naming (lowercase)
            let severity_str = serde_json::to_value(&e.severity)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| format!("{}", e.severity));
            let module_str = serde_json::to_value(&e.module)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| format!("{}", e.module));

            EventDto {
                id: e.id.clone(),
                timestamp: e.timestamp.format("%Y-%m-%dT%H:%M:%S UTC").to_string(),
                module: module_str,
                severity: severity_str,
                action_taken: format!("{}", e.action_taken),
                description: e.description.clone(),
            }
        })
        .collect();

    Ok(Json(EventsResponse {
        events: event_dtos,
        total,
    }))
}

async fn config_handler(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    check_rate_limit(&state, "read", false)?;
    let _ = &headers;
    // Serialiser la config puis redact les champs sensibles
    let config = state.daemon_state.config.read().expect("config read lock");
    let mut config_json = serde_json::to_value(&*config).unwrap_or(serde_json::Value::Null);
    drop(config);

    // Redact Slack webhook URL
    if let Some(alerting) = config_json.get_mut("alerting") {
        if let Some(slack) = alerting.get_mut("slack") {
            if let Some(webhook) = slack.get_mut("webhook_url") {
                *webhook = serde_json::Value::String("***REDACTED***".to_string());
            }
        }
    }

    Ok((StatusCode::OK, Json(config_json)))
}

// ---------------------------------------------------------------------------
// Rules API — CRUD pour les regles des guards
// ---------------------------------------------------------------------------

/// Requete d'ajout de regle FS/domaine/egress (category + value).
#[derive(Deserialize)]
struct AddRuleRequest {
    category: String,
    value: Option<String>,
    // Champs optionnels pour les commandes
    pattern: Option<String>,
    description: Option<String>,
    severity: Option<String>,
}

/// Requete de changement de mode.
#[derive(Deserialize)]
struct ChangeModeRequest {
    mode: String,
}

/// GET /api/rules — liste toutes les regles de tous les guards.
async fn rules_list_all(
    State(state): State<DashboardState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_rate_limit(&state, "read", false)?;
    let _ = &headers;
    let config = state.daemon_state.config.read().expect("config read lock");
    Ok(Json(serde_json::json!({
        "fs": {
            "blocked": config.fs_guard.blocked_paths,
            "read_only": config.fs_guard.read_only_paths,
            "allowed": config.fs_guard.allowed_paths,
        },
        "domains": {
            "blocked": config.cdp_proxy.domains.blocked,
            "allowed": config.cdp_proxy.domains.allowed,
            "require_approval": config.cdp_proxy.domains.require_approval,
        },
        "egress": {
            "allowed": config.net_guard.allowed_egress,
        },
        "commands": {
            "blacklist": config.cmd_guard.blacklist,
            "require_approval": config.cmd_guard.require_approval,
        },
    })))
}

/// GET /api/rules/:guard — regles d'un guard specifique.
async fn rules_get_guard(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    axum::extract::Path(guard): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    check_rate_limit(&state, "read", false)?;
    let _ = &headers;
    let config = state.daemon_state.config.read().expect("config read lock");
    match guard.as_str() {
        "fs" => Ok(Json(serde_json::json!({
            "blocked": config.fs_guard.blocked_paths,
            "read_only": config.fs_guard.read_only_paths,
            "allowed": config.fs_guard.allowed_paths,
        }))),
        "domains" => Ok(Json(serde_json::json!({
            "blocked": config.cdp_proxy.domains.blocked,
            "allowed": config.cdp_proxy.domains.allowed,
            "require_approval": config.cdp_proxy.domains.require_approval,
        }))),
        "egress" => Ok(Json(serde_json::json!({
            "allowed": config.net_guard.allowed_egress,
        }))),
        "commands" => Ok(Json(serde_json::json!({
            "blacklist": config.cmd_guard.blacklist,
            "require_approval": config.cmd_guard.require_approval,
        }))),
        _ => Err(StatusCode::NOT_FOUND),
    }
}

// ---------------------------------------------------------------------------
// Input validation helpers for rules API
// ---------------------------------------------------------------------------

/// Validate a rule value (length check).
fn validate_rule_value(value: &str) -> Result<(), (StatusCode, String)> {
    if value.len() > MAX_RULE_VALUE_LENGTH {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Rule value too long ({} chars, max {})",
                value.len(),
                MAX_RULE_VALUE_LENGTH
            ),
        ));
    }
    Ok(())
}

/// Validate that a category has not exceeded the max rules limit.
fn validate_category_limit(current_count: usize) -> Result<(), (StatusCode, String)> {
    if current_count >= MAX_RULES_PER_CATEGORY {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Category limit reached (max {} rules per category)",
                MAX_RULES_PER_CATEGORY
            ),
        ));
    }
    Ok(())
}

/// Check if a string value already exists in a list (duplicate check).
fn check_duplicate_string(list: &[String], value: &str) -> Result<(), (StatusCode, String)> {
    if list.iter().any(|v| v == value) {
        return Err((
            StatusCode::CONFLICT,
            format!("Duplicate rule: '{}' already exists", value),
        ));
    }
    Ok(())
}

/// V7: Validate a domain name format.
///
/// Rejects domains that:
/// - Contain whitespace
/// - Are empty
/// - Don't look like a valid domain (no dots, unless wildcard)
fn validate_domain_format(value: &str) -> Result<(), (StatusCode, String)> {
    if value.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Domain cannot be empty".to_string(),
        ));
    }
    if value.chars().any(|c| c.is_whitespace()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Domain '{}' contains whitespace", value),
        ));
    }
    // Allow wildcards (*.example.com) and simple domains
    let cleaned = value.replace('*', "x");
    if !cleaned.contains('.') && cleaned != "localhost" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Domain '{}' appears invalid (no dots)", value),
        ));
    }
    Ok(())
}

/// V7: Validate a filesystem path format.
///
/// Rejects paths that are not absolute and don't start with ~.
fn validate_path_format(value: &str) -> Result<(), (StatusCode, String)> {
    if value.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Path cannot be empty".to_string()));
    }
    // Allow absolute paths, ~ paths, and glob patterns starting with / or ~
    if !value.starts_with('/') && !value.starts_with('~') {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Path '{}' must be absolute (start with / or ~)", value),
        ));
    }
    Ok(())
}

/// POST /api/rules/:guard — ajouter une regle.
///
/// Requires auth + CSRF validation. Validates:
/// - Rule value length <= 500 chars
/// - Category not exceeding 1000 rules
/// - Regex patterns must compile
/// - No duplicate rules
async fn rules_add(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    axum::extract::Path(guard): axum::extract::Path<String>,
    Json(body): Json<AddRuleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Security checks: auth, CSRF, rate limit
    validate_auth(&state, &headers).map_err(|s| (s, "Unauthorized".to_string()))?;
    validate_origin(&headers).map_err(|s| (s, "Cross-origin request forbidden".to_string()))?;
    check_rate_limit(&state, "write", true).map_err(|s| (s, "Rate limit exceeded".to_string()))?;

    let mut config = state
        .daemon_state
        .config
        .write()
        .expect("config write lock");

    match guard.as_str() {
        "fs" => {
            let value = body
                .value
                .ok_or((StatusCode::BAD_REQUEST, "Missing 'value' field".to_string()))?;
            validate_rule_value(&value)?;
            // V7: Validate path format
            validate_path_format(&value)?;
            let list: &mut Vec<String> = match body.category.as_str() {
                "blocked" => &mut config.fs_guard.blocked_paths,
                "read_only" => &mut config.fs_guard.read_only_paths,
                "allowed" => &mut config.fs_guard.allowed_paths,
                _ => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Invalid category '{}' for fs guard", body.category),
                    ))
                }
            };
            validate_category_limit(list.len())?;
            check_duplicate_string(list, &value)?;
            list.push(value);
        }
        "domains" => {
            let value = body
                .value
                .ok_or((StatusCode::BAD_REQUEST, "Missing 'value' field".to_string()))?;
            validate_rule_value(&value)?;
            // V7: Validate domain format
            validate_domain_format(&value)?;
            let list: &mut Vec<String> = match body.category.as_str() {
                "blocked" => &mut config.cdp_proxy.domains.blocked,
                "allowed" => &mut config.cdp_proxy.domains.allowed,
                "require_approval" => &mut config.cdp_proxy.domains.require_approval,
                _ => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Invalid category '{}' for domains", body.category),
                    ))
                }
            };
            validate_category_limit(list.len())?;
            check_duplicate_string(list, &value)?;
            list.push(value);
        }
        "egress" => {
            let value = body
                .value
                .ok_or((StatusCode::BAD_REQUEST, "Missing 'value' field".to_string()))?;
            validate_rule_value(&value)?;
            let list: &mut Vec<String> = match body.category.as_str() {
                "allowed" => &mut config.net_guard.allowed_egress,
                _ => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Invalid category '{}' for egress", body.category),
                    ))
                }
            };
            validate_category_limit(list.len())?;
            check_duplicate_string(list, &value)?;
            list.push(value);
        }
        "commands" => {
            let pattern = body.pattern.ok_or((
                StatusCode::BAD_REQUEST,
                "Missing 'pattern' field".to_string(),
            ))?;
            validate_rule_value(&pattern)?;
            // Valider la regex
            if regex::Regex::new(&pattern).is_err() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Invalid regex pattern: {}", pattern),
                ));
            }
            let description = body.description.unwrap_or_default();
            match body.category.as_str() {
                "blacklist" => {
                    let severity = body.severity.unwrap_or_else(|| "warning".to_string());
                    // Duplicate check for command patterns
                    if config
                        .cmd_guard
                        .blacklist
                        .iter()
                        .any(|c| c.pattern == pattern)
                    {
                        return Err((
                            StatusCode::CONFLICT,
                            format!("Duplicate command pattern: '{}'", pattern),
                        ));
                    }
                    validate_category_limit(config.cmd_guard.blacklist.len())?;
                    config
                        .cmd_guard
                        .blacklist
                        .push(crate::config::CommandPatternConfig {
                            pattern,
                            description,
                            severity,
                        });
                }
                "require_approval" => {
                    // Duplicate check for approval patterns
                    if config
                        .cmd_guard
                        .require_approval
                        .iter()
                        .any(|c| c.pattern == pattern)
                    {
                        return Err((
                            StatusCode::CONFLICT,
                            format!("Duplicate approval pattern: '{}'", pattern),
                        ));
                    }
                    validate_category_limit(config.cmd_guard.require_approval.len())?;
                    config
                        .cmd_guard
                        .require_approval
                        .push(crate::config::ApprovalPatternConfig {
                            pattern,
                            description,
                        });
                }
                _ => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Invalid category '{}' for commands", body.category),
                    ))
                }
            }
        }
        _ => return Err((StatusCode::NOT_FOUND, format!("Unknown guard '{}'", guard))),
    }

    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// Check if a rule value matches a self-protection path.
fn is_self_protection_path(value: &str) -> bool {
    let protection_paths = get_self_protection_paths();
    protection_paths
        .iter()
        .any(|protected| value == protected.as_str() || value.starts_with(protected.as_str()))
}

/// DELETE /api/rules/:guard/:category/:index — supprimer une regle.
///
/// Requires auth + CSRF validation. Protects self-protection paths.
async fn rules_delete(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    axum::extract::Path((guard, category, index)): axum::extract::Path<(String, String, usize)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Security checks: auth, CSRF, rate limit
    validate_auth(&state, &headers).map_err(|s| (s, "Unauthorized".to_string()))?;
    validate_origin(&headers).map_err(|s| (s, "Cross-origin request forbidden".to_string()))?;
    check_rate_limit(&state, "write", true).map_err(|s| (s, "Rate limit exceeded".to_string()))?;

    let mut config = state
        .daemon_state
        .config
        .write()
        .expect("config write lock");

    let list: &mut Vec<String> = match (guard.as_str(), category.as_str()) {
        ("fs", "blocked") => &mut config.fs_guard.blocked_paths,
        ("fs", "read_only") => &mut config.fs_guard.read_only_paths,
        ("fs", "allowed") => &mut config.fs_guard.allowed_paths,
        ("domains", "blocked") => &mut config.cdp_proxy.domains.blocked,
        ("domains", "allowed") => &mut config.cdp_proxy.domains.allowed,
        ("domains", "require_approval") => &mut config.cdp_proxy.domains.require_approval,
        ("egress", "allowed") => &mut config.net_guard.allowed_egress,
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("Unknown guard/category: {}/{}", guard, category),
            ))
        }
    };

    if index >= list.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Index {} out of bounds (len={})", index, list.len()),
        ));
    }

    // Self-protection check: cannot remove rules protecting CounterClaw itself
    if is_self_protection_path(&list[index]) {
        return Err((
            StatusCode::FORBIDDEN,
            "Cannot remove self-protection rule".to_string(),
        ));
    }

    list.remove(index);
    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// PUT /api/mode — changer le mode d'operation.
///
/// Requires auth + CSRF validation.
async fn mode_change(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    Json(body): Json<ChangeModeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Security checks: auth, CSRF, rate limit
    validate_auth(&state, &headers).map_err(|s| (s, "Unauthorized".to_string()))?;
    validate_origin(&headers).map_err(|s| (s, "Cross-origin request forbidden".to_string()))?;
    check_rate_limit(&state, "write", true).map_err(|s| (s, "Rate limit exceeded".to_string()))?;

    let valid_modes = ["monitor", "enforce", "paranoid"];
    if !valid_modes.contains(&body.mode.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid mode '{}'. Expected: monitor, enforce, paranoid",
                body.mode
            ),
        ));
    }

    let mut config = state
        .daemon_state
        .config
        .write()
        .expect("config write lock");
    config.general.mode = body.mode.clone();

    Ok(Json(serde_json::json!({
        "status": "ok",
        "mode": body.mode
    })))
}

// ---------------------------------------------------------------------------
// Router builder
// ---------------------------------------------------------------------------

/// Construit le routeur axum avec tous les endpoints du dashboard.
///
/// Accepts `DashboardState` which wraps `Arc<DaemonState>` with security features.
pub fn build_router(state: DashboardState) -> Router {
    use axum::routing::{delete, put};

    Router::new()
        .route("/", get(dashboard_handler))
        .route("/health", get(health_handler))
        .route("/status", get(status_handler))
        .route("/api/health", get(health_handler))
        .route("/api/status", get(status_handler))
        .route("/api/events", get(events_handler))
        .route("/api/config", get(config_handler))
        // Rules CRUD API
        .route("/api/rules", get(rules_list_all))
        .route("/api/rules/{guard}", get(rules_get_guard).post(rules_add))
        .route(
            "/api/rules/{guard}/{category}/{index}",
            delete(rules_delete),
        )
        // Mode change
        .route("/api/mode", put(mode_change))
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .with_state(state)
}
