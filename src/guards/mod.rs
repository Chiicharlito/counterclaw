//! Modules de garde — implémentés en Phase 2 et 3.
//!
//! Chaque garde surveille un vecteur d'attaque différent :
//! - fs_guard : accès fichier
//! - cdp_proxy : contrôle du navigateur via Chrome DevTools Protocol
//! - net_guard : connexions réseau sortantes
//! - cmd_guard : commandes shell exécutées

pub mod adaptive_poller;
pub mod cdp_proxy;
pub mod cmd_guard;
pub mod fs_guard;
#[cfg(target_os = "macos")]
pub mod kqueue_monitor;
pub mod net_guard;
pub mod polling_monitor;
pub mod process_monitor;
