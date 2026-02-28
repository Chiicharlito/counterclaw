//! Dashboard HTTP server — endpoints JSON pour monitorer CounterClaw.
//!
//! Serveur axum léger qui expose l'état du daemon via une API REST.
//! Lit depuis Arc<DaemonState> (lecture seule, pas de mutation).

use crate::daemon::DaemonState;
use crate::types::{GuardModule, Severity};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Json;
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
// Handlers
// ---------------------------------------------------------------------------

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
    let mut config_json = serde_json::to_value(&state.config).unwrap_or(serde_json::Value::Null);

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
// Router builder
// ---------------------------------------------------------------------------

/// Construit le routeur axum avec tous les endpoints du dashboard.
pub fn build_router(state: Arc<DaemonState>) -> Router {
    Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/status", get(status_handler))
        .route("/api/events", get(events_handler))
        .route("/api/config", get(config_handler))
        .with_state(state)
}
