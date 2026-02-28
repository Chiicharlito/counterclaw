// ===== Build security: zero tolerance =====
#![deny(unsafe_code)]
#![deny(clippy::all)]

//! CounterClaw — AI Agent Guardian
//!
//! Ce crate expose les modules internes pour les tests d'intégration.
//! Le binaire est dans main.rs, la logique réutilisable est ici.

pub mod alerting;
pub mod config;
pub mod daemon;
pub mod dashboard;
pub mod guards;
pub mod launcher;
pub mod process;
pub mod types;
