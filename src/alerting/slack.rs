//! Slack notification backend — formate et envoie des alertes Slack.
//!
//! Utilise le format Block Kit pour des messages riches.
//! L'envoi HTTP est async via reqwest.

use crate::config::SlackConfig;
use crate::types::{SecurityEvent, Severity};
use std::time::Duration;

/// Nombre maximum de retries apres l'echec initial.
const MAX_RETRIES: u32 = 3;

/// Timeout par requete HTTP en secondes.
const REQUEST_TIMEOUT_SECS: u64 = 10;

/// Notificateur Slack — formate et envoie des alertes via webhook.
#[derive(Clone)]
pub struct SlackNotifier {
    enabled: bool,
    webhook_url: String,
    channel: String,
    min_severity: Severity,
    client: reqwest::Client,
}

impl SlackNotifier {
    /// Cree un nouveau notificateur depuis la configuration.
    /// Le client HTTP est configure avec un timeout de 10 secondes par requete.
    pub fn new(config: &SlackConfig) -> Self {
        let min_severity = parse_severity(&config.min_severity);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            enabled: config.enabled,
            webhook_url: config.webhook_url.clone(),
            channel: config.channel.clone(),
            min_severity,
            client,
        }
    }

    /// Retourne true si le notificateur est active.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Determine si un evenement doit etre notifie.
    /// Verifie que le notificateur est active et que la severite est suffisante.
    pub fn should_notify(&self, event: &SecurityEvent) -> bool {
        self.enabled && event.severity >= self.min_severity
    }

    /// Formate un SecurityEvent en message Slack Block Kit (JSON).
    pub fn format_message(&self, event: &SecurityEvent) -> serde_json::Value {
        let severity_emoji = match event.severity {
            Severity::Info => "\u{2139}\u{FE0F}",
            Severity::Warning => "\u{26A0}\u{FE0F}",
            Severity::High => "\u{1F534}",
            Severity::Critical => "\u{1F6A8}",
        };

        // Sanitize description for JSON safety
        let description = sanitize_for_slack(&event.description);
        let module_str = format!("{}", event.module);
        let severity_str = format!("{}", event.severity);
        let timestamp_str = event.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();

        serde_json::json!({
            "channel": self.channel,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": format!("{} CounterClaw Alert", severity_emoji)
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": format!("*Severity:*\n{}", severity_str)
                        },
                        {
                            "type": "mrkdwn",
                            "text": format!("*Module:*\n{}", module_str)
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": format!("*Description:*\n{}", description)
                    }
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": format!("Event ID: {} | {}", event.id, timestamp_str)
                        }
                    ]
                }
            ]
        })
    }

    /// Envoie un evenement via le webhook Slack.
    /// Utilise un backoff exponentiel : 1s, 2s, 4s entre les retries.
    /// Maximum 3 retries apres l'echec initial.
    pub async fn send(&self, event: &SecurityEvent) -> Result<(), String> {
        if !self.should_notify(event) {
            return Ok(());
        }

        let payload = self.format_message(event);

        // First attempt
        match self.post_webhook(&payload).await {
            Ok(()) => return Ok(()),
            Err(first_err) => {
                tracing::warn!("Slack webhook attempt 1 failed: {}", first_err);
            }
        }

        // Exponential backoff retries: 1s, 2s, 4s
        for retry in 0..MAX_RETRIES {
            let delay_secs = 1u64 << retry; // 1, 2, 4
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;

            match self.post_webhook(&payload).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(
                        "Slack webhook retry {} failed (waited {}s): {}",
                        retry + 1,
                        delay_secs,
                        e
                    );
                }
            }
        }

        Err(format!(
            "Slack webhook failed after {} retries with exponential backoff",
            MAX_RETRIES
        ))
    }

    /// POST vers le webhook Slack.
    async fn post_webhook(&self, payload: &serde_json::Value) -> Result<(), String> {
        let response = self
            .client
            .post(&self.webhook_url)
            .json(payload)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {}", e))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("Slack returned status: {}", response.status()))
        }
    }
}

/// Parse une chaine de severity en enum.
fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "warning" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Sanitize text for safe inclusion in Slack messages.
/// Escapes characters that could break JSON or Slack formatting.
fn sanitize_for_slack(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
