//! Dashboard HTTP server — endpoints JSON pour monitorer CounterClaw.
//!
//! Serveur axum léger qui expose l'état du daemon via une API REST.
//! Lit depuis Arc<DaemonState> (lecture seule, pas de mutation).

use crate::daemon::DaemonState;
use crate::types::{GuardModule, Severity};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, Json};
use axum::routing::get;
use axum::Router;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// DTOs — types sérialisables pour les réponses JSON
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

/// Parse une durée humaine ("2h", "30m", "60s") en chrono::Duration.
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
// Dashboard HTML — page inline, zéro dépendance externe
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
// Handlers
// ---------------------------------------------------------------------------

/// Sert la page HTML du dashboard.
async fn dashboard_handler() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%S UTC").to_string(),
    })
}

async fn status_handler(State(state): State<Arc<DaemonState>>) -> Json<StatusResponse> {
    let uptime = Utc::now() - state.start_time;
    let guards = state
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

    Json(StatusResponse {
        daemon_uptime_seconds: uptime.num_seconds(),
        mode: state.mode().to_string(),
        guards,
    })
}

async fn events_handler(
    State(state): State<Arc<DaemonState>>,
    Query(params): Query<EventsQuery>,
) -> Json<EventsResponse> {
    let limit = params.limit.unwrap_or(0);
    let min_severity = params.severity.as_deref().and_then(parse_severity);
    let module = params.module.as_deref().and_then(parse_module);
    let since = params
        .last
        .as_deref()
        .and_then(parse_duration)
        .map(|d| Utc::now() - d);

    let buf = state.event_buffer.read().expect("buffer lock");
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

    Json(EventsResponse {
        events: event_dtos,
        total,
    })
}

async fn config_handler(
    State(state): State<Arc<DaemonState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Sérialiser la config puis redact les champs sensibles
    let config = state.config.read().expect("config read lock");
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

    (StatusCode::OK, Json(config_json))
}

// ---------------------------------------------------------------------------
// Rules API — CRUD pour les règles des guards
// ---------------------------------------------------------------------------

/// Requête d'ajout de règle FS/domaine/egress (category + value).
#[derive(Deserialize)]
struct AddRuleRequest {
    category: String,
    value: Option<String>,
    // Champs optionnels pour les commandes
    pattern: Option<String>,
    description: Option<String>,
    severity: Option<String>,
}

/// Requête de changement de mode.
#[derive(Deserialize)]
struct ChangeModeRequest {
    mode: String,
}

/// GET /api/rules — liste toutes les règles de tous les guards.
async fn rules_list_all(State(state): State<Arc<DaemonState>>) -> Json<serde_json::Value> {
    let config = state.config.read().expect("config read lock");
    Json(serde_json::json!({
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
    }))
}

/// GET /api/rules/:guard — règles d'un guard spécifique.
async fn rules_get_guard(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Path(guard): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let config = state.config.read().expect("config read lock");
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

/// POST /api/rules/:guard — ajouter une règle.
async fn rules_add(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Path(guard): axum::extract::Path<String>,
    Json(body): Json<AddRuleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut config = state.config.write().expect("config write lock");

    match guard.as_str() {
        "fs" => {
            let value = body
                .value
                .ok_or((StatusCode::BAD_REQUEST, "Missing 'value' field".to_string()))?;
            match body.category.as_str() {
                "blocked" => config.fs_guard.blocked_paths.push(value),
                "read_only" => config.fs_guard.read_only_paths.push(value),
                "allowed" => config.fs_guard.allowed_paths.push(value),
                _ => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Invalid category '{}' for fs guard", body.category),
                    ))
                }
            }
        }
        "domains" => {
            let value = body
                .value
                .ok_or((StatusCode::BAD_REQUEST, "Missing 'value' field".to_string()))?;
            match body.category.as_str() {
                "blocked" => config.cdp_proxy.domains.blocked.push(value),
                "allowed" => config.cdp_proxy.domains.allowed.push(value),
                "require_approval" => config.cdp_proxy.domains.require_approval.push(value),
                _ => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Invalid category '{}' for domains", body.category),
                    ))
                }
            }
        }
        "egress" => {
            let value = body
                .value
                .ok_or((StatusCode::BAD_REQUEST, "Missing 'value' field".to_string()))?;
            match body.category.as_str() {
                "allowed" => config.net_guard.allowed_egress.push(value),
                _ => {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("Invalid category '{}' for egress", body.category),
                    ))
                }
            }
        }
        "commands" => {
            let pattern = body.pattern.ok_or((
                StatusCode::BAD_REQUEST,
                "Missing 'pattern' field".to_string(),
            ))?;
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

/// DELETE /api/rules/:guard/:category/:index — supprimer une règle.
async fn rules_delete(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Path((guard, category, index)): axum::extract::Path<(String, String, usize)>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut config = state.config.write().expect("config write lock");

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

    list.remove(index);
    Ok(Json(serde_json::json!({"status": "ok"})))
}

/// PUT /api/mode — changer le mode d'opération.
async fn mode_change(
    State(state): State<Arc<DaemonState>>,
    Json(body): Json<ChangeModeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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

    let mut config = state.config.write().expect("config write lock");
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
pub fn build_router(state: Arc<DaemonState>) -> Router {
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
        .with_state(state)
}
