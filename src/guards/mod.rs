//! Modules de garde — implémentés en Phase 2 et 3.
//!
//! Chaque garde surveille un vecteur d'attaque différent :
//! - fs_guard : accès fichier
//! - cdp_proxy : contrôle du navigateur via Chrome DevTools Protocol
//! - net_guard : connexions réseau sortantes
//! - cmd_guard : commandes shell exécutées

pub mod cdp_proxy;
pub mod fs_guard;
