//! Module d'alerting — le système nerveux central de CounterClaw.
//!
//! Quatre composants :
//! - `logger` : écrit les événements en JSON Lines dans un fichier
//! - `macos_notify` : envoie des notifications macOS natives
//! - `slack` : envoie des alertes via Slack webhook (Block Kit)
//! - `engine` : boucle centrale qui reçoit les événements et les dispatche

pub mod engine;
pub mod logger;
pub mod macos_notify;
pub mod slack;
