//! Tests pour le hot-reload de la config (Étape 2).
//!
//! Vérifie que :
//! - La config peut être rechargée depuis un fichier valide
//! - Un YAML invalide est rejeté et l'ancienne config est préservée
//! - Le mode d'opération change effectivement après un reload
//! - Les accès concurrents pendant un reload fonctionnent
//! - AppConfig::save() sérialise correctement la config vers un fichier

mod common;

use counterclaw::config::AppConfig;
use counterclaw::daemon::DaemonState;
use counterclaw::types::EventBuffer;
use std::sync::{Arc, RwLock};

fn setup_state_and_env() -> (Arc<DaemonState>, common::TestEnv) {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("valid config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = Arc::new(DaemonState::new(config, buffer));
    (state, env)
}

// ===========================================================================
// 1. reload_config — YAML valide
// ===========================================================================

#[test]
fn reload_valid_yaml_succeeds() {
    let (state, env) = setup_state_and_env();

    // Vérifier le mode initial
    assert_eq!(state.mode().to_string(), "monitor");

    // Écrire une nouvelle config avec mode enforce
    let new_yaml = common::minimal_monitor_config(&env).replace("mode: monitor", "mode: enforce");
    env.write_config(&new_yaml);

    // Reload
    let result = state.reload_config(&env.config_path());
    assert!(result.is_ok(), "Reload should succeed with valid YAML");
}

// ===========================================================================
// 2. reload_config — YAML invalide préserve l'ancienne config
// ===========================================================================

#[test]
fn reload_invalid_yaml_keeps_old_config() {
    let (state, env) = setup_state_and_env();

    // Vérifier le mode initial
    assert_eq!(state.mode().to_string(), "monitor");

    // Écrire du YAML invalide
    env.write_config("this is not: valid: yaml: [[[");

    // Reload devrait échouer
    let result = state.reload_config(&env.config_path());
    assert!(result.is_err(), "Reload should fail with invalid YAML");

    // L'ancienne config doit être préservée
    assert_eq!(
        state.mode().to_string(),
        "monitor",
        "Mode should still be monitor after failed reload"
    );
}

// ===========================================================================
// 3. reload_config — le mode change effectivement
// ===========================================================================

#[test]
fn reload_updates_mode() {
    let (state, env) = setup_state_and_env();

    assert_eq!(state.mode().to_string(), "monitor");

    // Passer en mode enforce
    let enforce_yaml =
        common::minimal_monitor_config(&env).replace("mode: monitor", "mode: enforce");
    env.write_config(&enforce_yaml);
    state.reload_config(&env.config_path()).unwrap();
    assert_eq!(state.mode().to_string(), "enforce");

    // Passer en mode paranoid
    let paranoid_yaml =
        common::minimal_monitor_config(&env).replace("mode: monitor", "mode: paranoid");
    env.write_config(&paranoid_yaml);
    state.reload_config(&env.config_path()).unwrap();
    assert_eq!(state.mode().to_string(), "paranoid");
}

// ===========================================================================
// 4. Accès concurrents pendant un reload
// ===========================================================================

#[test]
fn concurrent_access_during_reload() {
    let (state, env) = setup_state_and_env();

    // Lancer des lectures concurrentes pendant un reload
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let s = Arc::clone(&state);
            std::thread::spawn(move || {
                // Lecture du mode — ne doit pas paniquer
                let _ = s.mode().to_string();
                let _ = s.guard_statuses();
            })
        })
        .collect();

    // Reload pendant les lectures
    let enforce_yaml =
        common::minimal_monitor_config(&env).replace("mode: monitor", "mode: enforce");
    env.write_config(&enforce_yaml);
    let _ = state.reload_config(&env.config_path());

    // Attendre tous les threads
    for h in handles {
        h.join().expect("Thread should not panic");
    }
}

// ===========================================================================
// 5. reload_config — validation échoue, ancienne config préservée
// ===========================================================================

#[test]
fn reload_validation_failure_keeps_old() {
    let (state, env) = setup_state_and_env();

    // Écrire une config qui parse mais ne valide pas (mode invalide)
    let bad_yaml =
        common::minimal_monitor_config(&env).replace("mode: monitor", "mode: INVALID_MODE");
    env.write_config(&bad_yaml);

    let result = state.reload_config(&env.config_path());
    assert!(
        result.is_err(),
        "Reload should fail with invalid mode value"
    );

    // L'ancienne config doit être préservée
    assert_eq!(state.mode().to_string(), "monitor");
}

// ===========================================================================
// 6. AppConfig::save() — sérialisation vers fichier
// ===========================================================================

#[test]
fn config_save_writes_valid_yaml() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("valid config");

    // Sauvegarder dans un nouveau fichier
    let save_path = env.root().join("saved_config.yaml");
    config.save(&save_path).expect("save should succeed");

    // Recharger depuis le fichier sauvegardé
    let reloaded = AppConfig::load(&save_path).expect("saved config should be loadable");
    assert_eq!(reloaded.general.mode, config.general.mode);
    assert_eq!(reloaded.dashboard.port, config.dashboard.port);
    assert_eq!(reloaded.fs_guard.enabled, config.fs_guard.enabled);
}

#[test]
fn config_save_roundtrip_preserves_all_fields() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let original = AppConfig::load(&env.config_path()).expect("valid config");

    let save_path = env.root().join("roundtrip.yaml");
    original.save(&save_path).expect("save");
    let reloaded = AppConfig::load(&save_path).expect("reload");

    // Vérifier les champs critiques
    assert_eq!(reloaded.general.mode, original.general.mode);
    assert_eq!(reloaded.general.log_level, original.general.log_level);
    assert_eq!(
        reloaded.cdp_proxy.listen_port,
        original.cdp_proxy.listen_port
    );
    assert_eq!(
        reloaded.net_guard.max_post_payload_bytes,
        original.net_guard.max_post_payload_bytes
    );
    assert_eq!(
        reloaded.alerting.slack.channel,
        original.alerting.slack.channel
    );
    assert_eq!(
        reloaded.alerting.kill_switch.threshold_count,
        original.alerting.kill_switch.threshold_count
    );
}
