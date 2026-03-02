//! Tests pour l'AdaptivePoller — machine à états Idle/Active/Backoff.
//!
//! Vérifie les transitions d'état et les intervalles correspondants.

use counterclaw::guards::adaptive_poller::{AdaptivePoller, PollerState};
use std::time::Duration;

// ===========================================================================
// Test 1 : Idle → intervalle lent (30s par défaut)
// ===========================================================================

#[test]
fn idle_state_uses_slow_interval() {
    let poller = AdaptivePoller::new(Duration::from_millis(500));
    assert!(matches!(poller.state(), PollerState::Idle));
    assert_eq!(poller.current_interval(), Duration::from_secs(30));
}

// ===========================================================================
// Test 2 : Idle + watched=true → Active
// ===========================================================================

#[test]
fn transitions_to_active_when_process_found() {
    let mut poller = AdaptivePoller::new(Duration::from_millis(500));
    assert!(matches!(poller.state(), PollerState::Idle));

    poller.transition(true);
    assert!(matches!(poller.state(), PollerState::Active));
}

// ===========================================================================
// Test 3 : Active → intervalle rapide (configurable)
// ===========================================================================

#[test]
fn active_state_uses_fast_interval() {
    let mut poller = AdaptivePoller::new(Duration::from_millis(500));
    poller.transition(true); // Idle → Active
    assert_eq!(poller.current_interval(), Duration::from_millis(500));
}

// ===========================================================================
// Test 4 : Active + watched=false → Backoff
// ===========================================================================

#[test]
fn transitions_to_backoff_when_process_disappears() {
    let mut poller = AdaptivePoller::new(Duration::from_millis(500));
    poller.transition(true); // Idle → Active
    assert!(matches!(poller.state(), PollerState::Active));

    poller.transition(false); // Active → Backoff
    assert!(matches!(poller.state(), PollerState::Backoff));
}

// ===========================================================================
// Test 5 : Backoff × 3 → Idle
// ===========================================================================

#[test]
fn backoff_returns_to_idle_after_countdown() {
    let mut poller = AdaptivePoller::new(Duration::from_millis(500));
    poller.transition(true); // Idle → Active
    poller.transition(false); // Active → Backoff

    // Backoff has 3 ticks by default (3 transition(false) calls in Backoff)
    assert!(matches!(poller.state(), PollerState::Backoff));
    poller.transition(false); // tick 1 (remaining 3→2)
    assert!(matches!(poller.state(), PollerState::Backoff));
    poller.transition(false); // tick 2 (remaining 2→1)
    assert!(matches!(poller.state(), PollerState::Backoff));
    poller.transition(false); // tick 3 (remaining 1→0) → Idle
    assert!(
        matches!(poller.state(), PollerState::Idle),
        "Should return to Idle after backoff countdown"
    );
}

// ===========================================================================
// Test 6 : Backoff + watched=true → Active
// ===========================================================================

#[test]
fn backoff_returns_to_active_if_process_reappears() {
    let mut poller = AdaptivePoller::new(Duration::from_millis(500));
    poller.transition(true); // Idle → Active
    poller.transition(false); // Active → Backoff
    assert!(matches!(poller.state(), PollerState::Backoff));

    poller.transition(true); // Backoff → Active (process came back)
    assert!(matches!(poller.state(), PollerState::Active));
}

// ===========================================================================
// Test 7 : Active + watched=true → stays Active
// ===========================================================================

#[test]
fn stays_active_while_process_present() {
    let mut poller = AdaptivePoller::new(Duration::from_millis(500));
    poller.transition(true); // Idle → Active
    poller.transition(true); // Active → Active
    poller.transition(true); // Active → Active
    assert!(matches!(poller.state(), PollerState::Active));
}

// ===========================================================================
// Test 8 : constructeur avec intervalles custom
// ===========================================================================

#[test]
fn custom_intervals_respected() {
    let poller = AdaptivePoller::with_intervals(
        Duration::from_secs(60),    // idle
        Duration::from_millis(200), // active
        Duration::from_secs(10),    // backoff
        5,                          // backoff ticks
    );
    assert_eq!(poller.current_interval(), Duration::from_secs(60));

    let mut poller = poller;
    poller.transition(true);
    assert_eq!(poller.current_interval(), Duration::from_millis(200));

    poller.transition(false);
    assert_eq!(poller.current_interval(), Duration::from_secs(10));

    // Custom 5 ticks before returning to idle
    for _ in 0..4 {
        poller.transition(false);
        assert!(matches!(poller.state(), PollerState::Backoff));
    }
    poller.transition(false); // tick 5 → Idle
    assert!(matches!(poller.state(), PollerState::Idle));
}
