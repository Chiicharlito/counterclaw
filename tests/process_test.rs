//! Tests pour le module process — détection de processus OpenClaw.
//!
//! Organisation :
//! - Tests 1-6 : logique pure (matches_process_patterns)
//! - Tests 7-9 : ProcessScanner (intégration avec sysinfo)

mod common;

use counterclaw::process::{matches_process_patterns, ProcessInfo as ProcInfo, ProcessScanner};

// ===========================================================================
// Logique pure : matches_process_patterns
// ===========================================================================

/// Un nom exact dans la liste de patterns doit matcher.
#[test]
fn matches_exact_process_name() {
    let patterns = vec!["openclaw".to_string()];
    assert!(matches_process_patterns(
        "openclaw",
        "openclaw --serve",
        &patterns
    ));
}

/// Un pattern regex comme "node.*openclaw" doit matcher un process node.
#[test]
fn matches_regex_pattern() {
    let patterns = vec!["node.*openclaw".to_string()];
    assert!(matches_process_patterns(
        "node",
        "node /usr/lib/openclaw/server.js",
        &patterns
    ));
}

/// Un process sans rapport ne doit pas matcher.
#[test]
fn does_not_match_unrelated_process() {
    let patterns = vec!["openclaw".to_string(), "node.*openclaw".to_string()];
    assert!(!matches_process_patterns(
        "firefox",
        "firefox --new-tab",
        &patterns
    ));
}

/// Une liste de patterns vide ne matche jamais.
#[test]
fn handles_empty_patterns_list() {
    let patterns: Vec<String> = vec![];
    assert!(!matches_process_patterns("openclaw", "openclaw", &patterns));
}

/// Un nom de process vide ne doit pas matcher.
#[test]
fn handles_empty_process_name() {
    let patterns = vec!["openclaw".to_string()];
    assert!(!matches_process_patterns("", "", &patterns));
}

/// Un pattern regex invalide ne doit pas paniquer (il est ignoré silencieusement).
#[test]
fn invalid_regex_does_not_panic() {
    let patterns = vec!["[invalid(regex".to_string()];
    // Ne doit pas paniquer, retourne false
    assert!(!matches_process_patterns("openclaw", "openclaw", &patterns));
}

// ===========================================================================
// ProcessInfo construction
// ===========================================================================

/// On peut créer un ProcessInfo à partir de ses champs.
#[test]
fn creates_process_info_from_fields() {
    let info = ProcInfo {
        pid: 1234,
        name: "openclaw".to_string(),
        cmd: "openclaw --serve".to_string(),
        parent_pid: Some(1),
    };
    assert_eq!(info.pid, 1234);
    assert_eq!(info.name, "openclaw");
    assert_eq!(info.cmd, "openclaw --serve");
    assert_eq!(info.parent_pid, Some(1));
}

// ===========================================================================
// ProcessScanner (intégration avec sysinfo)
// ===========================================================================

/// Le scanner doit trouver le processus courant (le test lui-même).
#[test]
fn scanner_finds_current_process() {
    let scanner = ProcessScanner::new();
    // Le processus courant est le binaire de test — son nom contient "counterclaw" ou "process_test"
    let current_pid = std::process::id();
    let all = scanner.scan_all();
    // On doit trouver au moins un processus avec notre PID
    assert!(
        all.iter().any(|p| p.pid == current_pid),
        "Scanner should find the current test process (pid={})",
        current_pid
    );
}

/// Le scanner ne trouve rien pour un pattern inexistant.
#[test]
fn scanner_returns_empty_for_nonexistent() {
    let scanner = ProcessScanner::new();
    let results = scanner.find_matching(&["zzz_nonexistent_process_xyz_42".to_string()]);
    assert!(
        results.is_empty(),
        "Should find no process matching a nonexistent pattern"
    );
}
