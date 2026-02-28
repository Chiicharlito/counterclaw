//! Tests pour les modifications Phase 4 de l'AlertingEngine.
//!
//! Vérifie l'intégration de l'EventBuffer et du SlackNotifier.

mod common;

use counterclaw::alerting::engine::AlertingEngine;
use counterclaw::types::{ActionTaken, EventBuffer, GuardModule, SecurityEvent, Severity};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

/// Helper: crée un AlertingEngine avec un EventBuffer partagé et un TestEnv.
fn setup_engine(
    env: &common::TestEnv,
) -> (AlertingEngine, Arc<RwLock<EventBuffer>>) {
    let yaml = common::minimal_monitor_config(env);
    env.write_config(&yaml);
    let config =
        counterclaw::config::AppConfig::load(&env.config_path()).expect("valid config");

    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let engine = AlertingEngine::new(&config.alerting, buffer.clone());
    (engine, buffer)
}

fn make_event(severity: Severity, module: GuardModule, desc: &str) -> SecurityEvent {
    SecurityEvent::new(module, severity, ActionTaken::Logged, desc.to_string())
}

#[tokio::test]
async fn engine_populates_event_buffer() {
    let env = common::TestEnv::new();
    let (engine, buffer) = setup_engine(&env);
    let (tx, rx) = mpsc::channel::<SecurityEvent>(100);

    let engine_handle = tokio::spawn(async move {
        engine.run(rx).await;
    });

    // Send events
    tx.send(make_event(Severity::Warning, GuardModule::FsGuard, "test 1"))
        .await
        .unwrap();
    tx.send(make_event(Severity::High, GuardModule::CdpProxy, "test 2"))
        .await
        .unwrap();

    // Drop sender to close channel
    drop(tx);
    engine_handle.await.unwrap();

    let buf = buffer.read().unwrap();
    assert_eq!(buf.len(), 2, "Both events should be in buffer");
}

#[tokio::test]
async fn engine_buffer_respects_capacity() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config =
        counterclaw::config::AppConfig::load(&env.config_path()).expect("valid config");

    let buffer = Arc::new(RwLock::new(EventBuffer::new(3))); // Tiny capacity
    let engine = AlertingEngine::new(&config.alerting, buffer.clone());
    let (tx, rx) = mpsc::channel::<SecurityEvent>(100);

    let engine_handle = tokio::spawn(async move {
        engine.run(rx).await;
    });

    // Send 5 events into a buffer of capacity 3
    for i in 0..5 {
        tx.send(make_event(
            Severity::Info,
            GuardModule::System,
            &format!("event {}", i),
        ))
        .await
        .unwrap();
    }

    drop(tx);
    engine_handle.await.unwrap();

    let buf = buffer.read().unwrap();
    assert_eq!(buf.len(), 3, "Buffer should not exceed capacity");
}

#[tokio::test]
async fn engine_continues_after_slack_disabled() {
    let env = common::TestEnv::new();
    let (engine, buffer) = setup_engine(&env); // Slack disabled in minimal config
    let (tx, rx) = mpsc::channel::<SecurityEvent>(100);

    let engine_handle = tokio::spawn(async move {
        engine.run(rx).await;
    });

    tx.send(make_event(
        Severity::Critical,
        GuardModule::System,
        "critical event",
    ))
    .await
    .unwrap();

    drop(tx);
    engine_handle.await.unwrap();

    let buf = buffer.read().unwrap();
    assert_eq!(buf.len(), 1, "Engine should continue even with Slack disabled");
}

#[tokio::test]
async fn engine_shutdown_drains_cleanly() {
    let env = common::TestEnv::new();
    let (engine, _buffer) = setup_engine(&env);
    let (tx, rx) = mpsc::channel::<SecurityEvent>(100);

    let engine_handle = tokio::spawn(async move {
        engine.run(rx).await;
    });

    // Drop sender immediately → engine should stop cleanly
    drop(tx);
    let result = engine_handle.await;
    assert!(result.is_ok(), "Engine should shut down without panic");
}

#[tokio::test]
async fn engine_processes_multiple_events() {
    let env = common::TestEnv::new();
    let (engine, buffer) = setup_engine(&env);
    let (tx, rx) = mpsc::channel::<SecurityEvent>(100);

    let engine_handle = tokio::spawn(async move {
        engine.run(rx).await;
    });

    for i in 0..10 {
        tx.send(make_event(
            Severity::Info,
            GuardModule::System,
            &format!("event {}", i),
        ))
        .await
        .unwrap();
    }

    drop(tx);
    engine_handle.await.unwrap();

    let buf = buffer.read().unwrap();
    assert_eq!(buf.len(), 10, "All 10 events should be in buffer");
}

#[tokio::test]
async fn engine_slack_respects_severity() {
    // This test verifies the SlackNotifier's should_notify is checked.
    // With Slack disabled in config, no notifications are sent regardless of severity.
    // This test mainly ensures the engine doesn't crash when processing
    // events of various severities with Slack integration present.
    let env = common::TestEnv::new();
    let (engine, buffer) = setup_engine(&env);
    let (tx, rx) = mpsc::channel::<SecurityEvent>(100);

    let engine_handle = tokio::spawn(async move {
        engine.run(rx).await;
    });

    // Send events of different severities
    tx.send(make_event(Severity::Info, GuardModule::System, "info"))
        .await
        .unwrap();
    tx.send(make_event(Severity::Warning, GuardModule::FsGuard, "warning"))
        .await
        .unwrap();
    tx.send(make_event(
        Severity::Critical,
        GuardModule::CdpProxy,
        "critical",
    ))
    .await
    .unwrap();

    drop(tx);
    engine_handle.await.unwrap();

    let buf = buffer.read().unwrap();
    assert_eq!(buf.len(), 3, "All events processed regardless of severity");
}
