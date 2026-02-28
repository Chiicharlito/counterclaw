mod common;

use chrono::{Duration, Utc};
use counterclaw::types::{ActionTaken, EventBuffer, GuardModule, SecurityEvent, Severity};

/// Helper to create a test event with specific module and severity.
fn make_event(module: GuardModule, severity: Severity) -> SecurityEvent {
    SecurityEvent::new(
        module,
        severity,
        ActionTaken::Logged,
        "test event".to_string(),
    )
}

fn make_event_with_desc(module: GuardModule, severity: Severity, desc: &str) -> SecurityEvent {
    SecurityEvent::new(module, severity, ActionTaken::Logged, desc.to_string())
}

#[test]
fn push_and_retrieve() {
    let mut buffer = EventBuffer::new(10);
    buffer.push(make_event(GuardModule::System, Severity::Info));
    buffer.push(make_event(GuardModule::FsGuard, Severity::Warning));
    buffer.push(make_event(GuardModule::CdpProxy, Severity::High));

    assert_eq!(buffer.len(), 3);
}

#[test]
fn evicts_oldest_at_capacity() {
    let mut buffer = EventBuffer::new(5);
    for i in 0..7 {
        buffer.push(make_event_with_desc(
            GuardModule::System,
            Severity::Info,
            &format!("event {}", i),
        ));
    }

    assert_eq!(buffer.len(), 5, "Should evict oldest to stay at capacity");

    // The oldest 2 (event 0, event 1) should be gone
    // Query all, most recent first
    let all = buffer.query(0, None, None, None);
    assert_eq!(all.len(), 5);
    // Most recent should be "event 6"
    assert_eq!(all[0].description, "event 6");
    // Oldest remaining should be "event 2"
    assert_eq!(all[4].description, "event 2");
}

#[test]
fn query_by_severity() {
    let mut buffer = EventBuffer::new(10);
    buffer.push(make_event(GuardModule::System, Severity::Info));
    buffer.push(make_event(GuardModule::System, Severity::Warning));
    buffer.push(make_event(GuardModule::System, Severity::High));
    buffer.push(make_event(GuardModule::System, Severity::Critical));

    let high_plus = buffer.query(0, Some(&Severity::High), None, None);
    assert_eq!(high_plus.len(), 2, "Should get High and Critical only");
}

#[test]
fn query_by_module() {
    let mut buffer = EventBuffer::new(10);
    buffer.push(make_event(GuardModule::FsGuard, Severity::Info));
    buffer.push(make_event(GuardModule::CdpProxy, Severity::Info));
    buffer.push(make_event(GuardModule::FsGuard, Severity::Warning));
    buffer.push(make_event(GuardModule::System, Severity::Info));

    let fs_only = buffer.query(0, None, Some(&GuardModule::FsGuard), None);
    assert_eq!(fs_only.len(), 2, "Should get FsGuard events only");
}

#[test]
fn query_with_limit() {
    let mut buffer = EventBuffer::new(10);
    for _ in 0..8 {
        buffer.push(make_event(GuardModule::System, Severity::Info));
    }

    let limited = buffer.query(2, None, None, None);
    assert_eq!(limited.len(), 2, "limit=2 should return max 2");
}

#[test]
fn query_since_timestamp() {
    let mut buffer = EventBuffer::new(10);

    // Push an old event manually
    let mut old_event = make_event(GuardModule::System, Severity::Info);
    old_event.timestamp = Utc::now() - Duration::hours(2);
    old_event.description = "old".to_string();
    buffer.push(old_event);

    // Push a recent event
    let recent = make_event(GuardModule::System, Severity::Warning);
    buffer.push(recent);

    let since = Utc::now() - Duration::hours(1);
    let recent_only = buffer.query(0, None, None, Some(since));
    assert_eq!(recent_only.len(), 1, "Should get only events after since");
}

#[test]
fn empty_buffer_is_empty() {
    let buffer = EventBuffer::new(10);
    assert!(buffer.is_empty());
    assert_eq!(buffer.len(), 0);

    let results = buffer.query(0, None, None, None);
    assert!(results.is_empty());
}

#[test]
fn combined_filters() {
    let mut buffer = EventBuffer::new(20);

    // Mix of events
    buffer.push(make_event(GuardModule::FsGuard, Severity::Info));
    buffer.push(make_event(GuardModule::FsGuard, Severity::Critical));
    buffer.push(make_event(GuardModule::CdpProxy, Severity::Critical));
    buffer.push(make_event(GuardModule::FsGuard, Severity::High));
    buffer.push(make_event(GuardModule::System, Severity::High));

    // FsGuard + High+ + limit 1
    let result = buffer.query(1, Some(&Severity::High), Some(&GuardModule::FsGuard), None);
    assert_eq!(result.len(), 1, "Combined filters with limit should work");
}
