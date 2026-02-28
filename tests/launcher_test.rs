//! Tests for the launcher module (launchd plist generation + launchctl commands).

mod common;

use counterclaw::launcher::{build_launchctl_command, generate_plist, plist_install_path};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// generate_plist — XML plist generation
// ---------------------------------------------------------------------------

#[test]
fn generate_plist_contains_label() {
    let plist = generate_plist("io.counterclaw.daemon", "/usr/local/bin/counterclaw", None);
    assert!(
        plist.contains("<string>io.counterclaw.daemon</string>"),
        "plist should contain the label"
    );
}

#[test]
fn generate_plist_contains_binary_path() {
    let plist = generate_plist(
        "io.counterclaw.daemon",
        "/usr/local/bin/counterclaw",
        Some("/home/user/.counterclaw/config.yaml"),
    );
    assert!(
        plist.contains("<string>/usr/local/bin/counterclaw</string>"),
        "plist should contain the binary path"
    );
}

#[test]
fn generate_plist_contains_config_argument() {
    let plist = generate_plist(
        "io.counterclaw.daemon",
        "/usr/local/bin/counterclaw",
        Some("/home/user/.counterclaw/config.yaml"),
    );
    assert!(
        plist.contains("<string>--config</string>"),
        "plist should contain --config flag"
    );
    assert!(
        plist.contains("<string>/home/user/.counterclaw/config.yaml</string>"),
        "plist should contain the config path"
    );
}

#[test]
fn generate_plist_has_keep_alive() {
    let plist = generate_plist("io.counterclaw.daemon", "/usr/local/bin/counterclaw", None);
    assert!(
        plist.contains("<key>KeepAlive</key>"),
        "plist should have KeepAlive key"
    );
    assert!(
        plist.contains("<true/>"),
        "plist should have KeepAlive set to true"
    );
}

#[test]
fn generate_plist_has_log_paths() {
    let plist = generate_plist("io.counterclaw.daemon", "/usr/local/bin/counterclaw", None);
    assert!(
        plist.contains("<key>StandardOutPath</key>"),
        "plist should have StandardOutPath"
    );
    assert!(
        plist.contains("<key>StandardErrorPath</key>"),
        "plist should have StandardErrorPath"
    );
    assert!(
        plist.contains("counterclaw-stdout.log"),
        "stdout log path should contain counterclaw-stdout.log"
    );
    assert!(
        plist.contains("counterclaw-stderr.log"),
        "stderr log path should contain counterclaw-stderr.log"
    );
}

#[test]
fn generate_plist_has_run_at_load_false() {
    let plist = generate_plist("io.counterclaw.daemon", "/usr/local/bin/counterclaw", None);
    assert!(
        plist.contains("<key>RunAtLoad</key>"),
        "plist should have RunAtLoad key"
    );
    // RunAtLoad should be false — user controls when to start
    assert!(plist.contains("<false/>"), "RunAtLoad should be false");
}

#[test]
fn generate_plist_is_valid_xml() {
    let plist = generate_plist("io.counterclaw.daemon", "/usr/local/bin/counterclaw", None);
    assert!(
        plist.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
        "plist should start with XML declaration"
    );
    assert!(
        plist.contains("<!DOCTYPE plist"),
        "plist should contain DOCTYPE"
    );
    assert!(
        plist.contains("<plist version=\"1.0\">"),
        "plist should contain plist element"
    );
    assert!(
        plist.contains("</plist>"),
        "plist should have closing plist tag"
    );
    assert!(
        plist.contains("<dict>"),
        "plist should contain dict element"
    );
    assert!(
        plist.contains("</dict>"),
        "plist should have closing dict tag"
    );
}

#[test]
fn generate_plist_without_config_omits_config_args() {
    let plist = generate_plist("io.counterclaw.daemon", "/usr/local/bin/counterclaw", None);
    assert!(
        !plist.contains("--config"),
        "plist without config should not contain --config flag"
    );
}

// ---------------------------------------------------------------------------
// plist_install_path — returns path in ~/Library/LaunchAgents
// ---------------------------------------------------------------------------

#[test]
fn plist_install_path_is_in_launch_agents() {
    let path = plist_install_path("io.counterclaw.daemon");
    let path_str = path.to_string_lossy();
    assert!(
        path_str.contains("Library/LaunchAgents"),
        "plist should be installed in Library/LaunchAgents, got: {}",
        path_str
    );
    assert!(
        path_str.ends_with("io.counterclaw.daemon.plist"),
        "plist filename should be label.plist, got: {}",
        path_str
    );
}

// ---------------------------------------------------------------------------
// build_launchctl_command — constructs launchctl CLI commands
// ---------------------------------------------------------------------------

#[test]
fn build_launchctl_load_command() {
    let plist_path = PathBuf::from("/Users/test/Library/LaunchAgents/io.counterclaw.daemon.plist");
    let cmd = build_launchctl_command("load", &plist_path);
    assert_eq!(cmd[0], "launchctl");
    assert_eq!(cmd[1], "load");
    assert_eq!(cmd[2], plist_path.to_string_lossy());
}

#[test]
fn build_launchctl_unload_command() {
    let plist_path = PathBuf::from("/Users/test/Library/LaunchAgents/io.counterclaw.daemon.plist");
    let cmd = build_launchctl_command("unload", &plist_path);
    assert_eq!(cmd[0], "launchctl");
    assert_eq!(cmd[1], "unload");
    assert_eq!(cmd[2], plist_path.to_string_lossy());
}

// ---------------------------------------------------------------------------
// Security — XML escaping
// ---------------------------------------------------------------------------

#[test]
fn generate_plist_escapes_xml_special_chars() {
    let plist = generate_plist("io.counterclaw.daemon", "/usr/local/bin/counter&claw", None);
    assert!(
        !plist.contains("/usr/local/bin/counter&claw"),
        "ampersand should be escaped in XML"
    );
    assert!(
        plist.contains("/usr/local/bin/counter&amp;claw"),
        "ampersand should become &amp;"
    );
}

#[test]
fn generate_plist_escapes_angle_brackets() {
    let plist = generate_plist(
        "io.counterclaw.daemon",
        "/usr/local/bin/counterclaw",
        Some("/path/with<brackets>/config.yaml"),
    );
    assert!(
        !plist.contains("/path/with<brackets>"),
        "angle brackets should be escaped in XML"
    );
    assert!(
        plist.contains("/path/with&lt;brackets&gt;/config.yaml"),
        "angle brackets should become &lt; and &gt;"
    );
}
