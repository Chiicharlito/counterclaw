//! Dashboard HTTP — implémenté en Phase 4, HTML ajouté post-Phase 5.
//!
//! Serveur axum sur :9999 avec :
//! - / : page HTML dashboard (dark theme, auto-refresh 5s)
//! - /health, /status : raccourcis vers les endpoints JSON
//! - /api/health : santé du daemon
//! - /api/status : état des modules
//! - /api/events : derniers événements
//! - /api/config : configuration active (webhook redacted)

pub mod server;
