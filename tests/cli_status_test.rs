//! Tests de la commande CLI `status`.

mod common;

use predicates::prelude::*;

#[allow(deprecated)]
fn counterclaw_cmd() -> assert_cmd::Command {
    assert_cmd::Command::cargo_bin("counterclaw").unwrap()
}

#[test]
fn status_no_pid_exits_1() {
    // Sans config spécifique, le PID file par défaut n'existe pas
    // → doit indiquer que CounterClaw ne tourne pas
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);

    counterclaw_cmd()
        .args(["status", "-c", &env.config_path().to_string_lossy()])
        .assert()
        .failure();
}

#[test]
fn status_no_pid_shows_not_running() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);

    counterclaw_cmd()
        .args(["status", "-c", &env.config_path().to_string_lossy()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("not running"));
}

#[test]
fn status_help_shows_command() {
    counterclaw_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("status"));
}

#[test]
fn status_stale_pid_exits_1() {
    // PID file exists but no process with that PID
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);

    // Write a fake PID file with a PID that doesn't exist
    let pid_path = env.root().join("counterclaw.pid");
    std::fs::write(&pid_path, "999999").unwrap();

    counterclaw_cmd()
        .args(["status", "-c", &env.config_path().to_string_lossy()])
        .assert()
        .failure()
        .stdout(predicate::str::contains("not running"));
}

#[test]
fn status_unreachable_dashboard() {
    // PID file exists with current process PID (simulates running daemon)
    // but dashboard is not listening
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);

    // Write our own PID (we know it exists)
    let pid_path = env.root().join("counterclaw.pid");
    std::fs::write(&pid_path, std::process::id().to_string()).unwrap();

    counterclaw_cmd()
        .args(["status", "-c", &env.config_path().to_string_lossy()])
        .assert()
        .failure()
        .stdout(
            predicate::str::is_match("unreachable|connection refused|not responding")
                .unwrap()
                .from_utf8(),
        );
}
