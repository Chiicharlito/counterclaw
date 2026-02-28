//! Dashboard HTTP — implémenté en Phase 4.
//!
//! Serveur axum sur :9999 avec des endpoints JSON :
//! - /api/health : santé du daemon
//! - /api/status : état des modules
//! - /api/events : derniers événements
//! - /api/config : configuration active (webhook redacted)

pub mod server;
