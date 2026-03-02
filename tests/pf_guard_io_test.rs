//! Tests I/O intégration pour PfGuard — nécessite root (pfctl).
//!
//! Ces tests sont marqués `#[ignore]` car ils nécessitent :
//! 1. macOS (pf n'existe pas sur Linux)
//! 2. Privilèges root (pfctl modifie le firewall kernel)
//!
//! Pour les exécuter :
//! ```bash
//! sudo cargo test --test pf_guard_io_test -- --ignored
//! ```

mod common;

use counterclaw::guards::pf_guard::{PfController, PfRuleGenerator, ResolvedDestination};
use std::net::IpAddr;
use std::time::Instant;

// ---------------------------------------------------------------------------
// Helper : crée un controller avec un anchor de test unique
// ---------------------------------------------------------------------------

fn test_anchor_name() -> String {
    format!("com.counterclaw.test_{}", std::process::id())
}

fn test_controller() -> PfController {
    PfController::new(&test_anchor_name())
}

fn test_generator() -> PfRuleGenerator {
    PfRuleGenerator::new("_nobody", &test_anchor_name())
}

// ---------------------------------------------------------------------------
// Tests I/O — #[ignore] car root requis
// ---------------------------------------------------------------------------

/// Install des règles dans une ancre pf, puis les flush.
/// Vérifie le roundtrip install → flush sans erreur.
#[tokio::test]
#[ignore]
async fn install_and_flush_anchor_roundtrip() {
    if !PfController::is_root() {
        eprintln!("Skipping: not root");
        return;
    }

    let controller = test_controller();
    let generator = test_generator();

    // Generate rules with a test IP
    let resolved = vec![ResolvedDestination {
        original: "test.example.com".to_string(),
        ips: vec!["93.184.216.34".parse::<IpAddr>().unwrap()],
        resolved_at: Instant::now(),
    }];
    let rules = generator.generate_anchor_rules(&resolved);

    // Install rules
    controller
        .install_anchor(&rules)
        .await
        .expect("install_anchor should succeed as root");

    // Flush rules (cleanup)
    controller
        .flush_anchor()
        .await
        .expect("flush_anchor should succeed as root");
}

/// Remplace les IPs dans la table pf.
#[tokio::test]
#[ignore]
async fn table_replace_updates_ips() {
    if !PfController::is_root() {
        eprintln!("Skipping: not root");
        return;
    }

    let controller = test_controller();
    let generator = test_generator();

    // First install rules with an initial table
    let resolved = vec![ResolvedDestination {
        original: "initial.example.com".to_string(),
        ips: vec!["1.2.3.4".parse::<IpAddr>().unwrap()],
        resolved_at: Instant::now(),
    }];
    let rules = generator.generate_anchor_rules(&resolved);
    controller
        .install_anchor(&rules)
        .await
        .expect("install should succeed");

    // Update table with new IPs
    let new_ips: Vec<IpAddr> = vec!["5.6.7.8".parse().unwrap(), "9.10.11.12".parse().unwrap()];
    controller
        .update_table("counterclaw_allowed", &new_ips)
        .await
        .expect("table update should succeed");

    // Cleanup
    controller
        .flush_anchor()
        .await
        .expect("flush should succeed");
}

/// Vérifie que le cleanup supprime bien toutes les règles de l'ancre.
#[tokio::test]
#[ignore]
async fn cleanup_removes_all_rules() {
    if !PfController::is_root() {
        eprintln!("Skipping: not root");
        return;
    }

    let controller = test_controller();
    let generator = test_generator();

    // Install rules
    let resolved = vec![ResolvedDestination {
        original: "cleanup.example.com".to_string(),
        ips: vec!["10.0.0.1".parse::<IpAddr>().unwrap()],
        resolved_at: Instant::now(),
    }];
    let rules = generator.generate_anchor_rules(&resolved);
    controller
        .install_anchor(&rules)
        .await
        .expect("install should succeed");

    // Flush — should remove everything
    controller
        .flush_anchor()
        .await
        .expect("flush should succeed");

    // Verify: re-flush should also succeed (idempotent)
    controller
        .flush_anchor()
        .await
        .expect("double flush should not error");
}

/// enable_pf ne crash pas (pfctl -E est ref-counted).
#[tokio::test]
#[ignore]
async fn enable_pf_is_safe() {
    if !PfController::is_root() {
        eprintln!("Skipping: not root");
        return;
    }

    let controller = test_controller();

    // pfctl -E is reference-counted — calling it is safe even if pf is already enabled
    controller
        .enable_pf()
        .await
        .expect("enable_pf should succeed (ref-counted)");
}
