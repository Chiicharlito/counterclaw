//! Security tests for launcher hardening (Phase 0 + Phase 3)

mod common;

use counterclaw::launcher::*;

// Step 0.1 — InstallMode

#[test]
fn generates_daemon_mode_plist_with_root_paths() {
    let plist = generate_plist_for_mode(
        "io.counterclaw.daemon",
        "/usr/local/bin/counterclaw",
        Some("/etc/counterclaw/config.yaml"),
        InstallMode::Daemon,
    );
    assert!(
        plist.contains("<true/>"),
        "RunAtLoad should be true for daemon mode"
    );
    assert!(
        plist.contains("/var/log/counterclaw/"),
        "Should use /var/log for daemon"
    );
    assert!(plist.contains("io.counterclaw.daemon"));
    assert!(plist.contains("/usr/local/bin/counterclaw"));
    assert!(plist.contains("/etc/counterclaw/config.yaml"));
}

#[test]
fn generates_agent_mode_plist_with_user_paths() {
    let plist = generate_plist_for_mode(
        "io.counterclaw.daemon",
        "/usr/local/bin/counterclaw",
        None,
        InstallMode::Agent,
    );
    assert!(
        plist.contains("<false/>"),
        "RunAtLoad should be false for agent mode"
    );
    assert!(
        plist.contains("/tmp/counterclaw-stdout.log"),
        "Should use /tmp for agent"
    );
}

#[test]
fn daemon_plist_path_is_library_launchdaemons() {
    let path = plist_install_path_for_mode("io.counterclaw.daemon", InstallMode::Daemon);
    assert_eq!(
        path.to_string_lossy(),
        "/Library/LaunchDaemons/io.counterclaw.daemon.plist"
    );
}

#[test]
fn agent_plist_path_is_home_launchagents() {
    let path = plist_install_path_for_mode("io.counterclaw.daemon", InstallMode::Agent);
    let home = dirs::home_dir().unwrap();
    let expected = home.join("Library/LaunchAgents/io.counterclaw.daemon.plist");
    assert_eq!(path, expected);
}

#[test]
fn existing_generate_plist_still_works() {
    // Backward compatibility
    let plist = generate_plist("io.counterclaw.daemon", "/usr/local/bin/counterclaw", None);
    assert!(plist.contains("io.counterclaw.daemon"));
    assert!(plist.contains("/usr/local/bin/counterclaw"));
}

// Step 3.7 — Plist integrity

#[test]
fn compute_plist_hash_deterministic() {
    let content = "test plist content";
    let hash1 = compute_plist_hash(content);
    let hash2 = compute_plist_hash(content);
    assert_eq!(hash1, hash2);
}

#[test]
fn detects_plist_tampering() {
    let env = common::TestEnv::new();
    let plist_path = env.root().join("test.plist");
    let content = "<plist>original</plist>";
    std::fs::write(&plist_path, content).unwrap();

    let hash = compute_plist_hash(content);

    // Should match
    assert!(verify_plist_integrity(&plist_path, hash).unwrap());

    // Tamper with the file
    std::fs::write(&plist_path, "<plist>tampered</plist>").unwrap();

    // Should detect tampering
    assert!(!verify_plist_integrity(&plist_path, hash).unwrap());
}

#[test]
fn plist_integrity_error_on_missing_file() {
    let result = verify_plist_integrity(std::path::Path::new("/nonexistent.plist"), 0);
    assert!(result.is_err());
}
