//! Module d'alerting — le système nerveux central de CounterClaw.
//!
//! Trois composants :
//! - `logger` : écrit les événements en JSON Lines dans un fichier
//! - `macos_notify` : envoie des notifications macOS natives
//! - `engine` : boucle centrale qui reçoit les événements et les dispatche

pub mod engine;
pub mod logger;
pub mod macos_notify;
