# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CounterClaw is an OS-level daemon (Rust) that protects machines from autonomous AI agents (like OpenClaw) exfiltrating sensitive data. It runs independently from the AI agent — no plugin, no skill, no prompt can disable it.

**Status**: Phases 1-4 complete. 237 tests passing. Phase 5 (packaging) remaining. `PROJECT_OVERVIEW.md` is the single source of truth for the full technical specification (written in French).

**Target**: macOS primary, Linux secondary.

## Build Commands

```bash
cargo build                    # Debug build
cargo build --release          # Release build → ./target/release/counterclaw
cargo test                     # Run all tests
cargo test <test_name>         # Run a single test
cargo clippy -- -D warnings    # Lint (must pass with zero warnings)
cargo fmt --check              # Check formatting
cargo fmt                      # Auto-format
```

## Architecture

Four independent guard modules + alerting engine, all communicating via `tokio::sync::mpsc` channels:

```
                    ┌─────────────────────────────────────┐
                    │         CounterClaw Daemon           │
                    │                                      │
                    │  FS Guard ─────┐                     │
                    │  CDP Proxy ────┤ mpsc::channel       │
                    │  Net Guard ────┤ → Alerting Engine   │
                    │  Cmd Guard ────┘   ├─ macOS notify   │
                    │                    ├─ Slack webhook   │
                    │                    ├─ JSON Lines log  │
                    │                    └─ Kill Switch     │
                    │                                      │
                    │  Dashboard (axum HTTP on :9999)       │
                    │  CLI (clap)                           │
                    └─────────────────────────────────────┘
```

- **FS Guard** — Watches filesystem via `notify` crate (FSEvents on macOS). Blocks access to sensitive paths (~/.ssh, ~/.aws, etc.). Kills offending processes.
- **CDP Proxy** — **Core value differentiator.** Transparent WebSocket proxy between AI agent and Chrome DevTools Protocol. Intercepts every CDP JSON-RPC message, blocks banned domains, filters dangerous CDP commands, detects exfiltration via regex. Listens on :18792, forwards to Chrome on :18800.
- **Net Guard** — Monitors outbound connections from AI agent processes via sysinfo/lsof polling. MVP is log-only.
- **Cmd Guard** — Monitors shell commands spawned by agent. Blocks dangerous patterns (curl|sh, rm -rf /, keychain access). MVP uses process polling (1-2s latency).
- **Alerting Engine** — Central dispatcher receiving `SecurityEvent` from all modules. Routes to notification backends. Kill switch suspends the agent after N violations in M seconds.

### Guard Trait

All guard modules implement a common trait for uniform lifecycle management:

```rust
#[async_trait::async_trait]
pub trait Guard: Send + Sync {
    fn name(&self) -> &str;
    async fn start(&self, alert_tx: mpsc::Sender<SecurityEvent>) -> anyhow::Result<()>;
    async fn stop(&self) -> anyhow::Result<()>;
    fn status(&self) -> GuardStatus;
}
```

Each module runs in its own `tokio::task`.

## Source Layout

```
src/
├── main.rs              # CLI entry point (clap) + daemon bootstrap
├── lib.rs               # Public crate root (exposes modules for tests)
├── config.rs            # YAML config parsing + validation          ✅ Phase 1
├── types.rs             # Shared types: SecurityEvent, Severity...  ✅ Phase 1
├── process.rs           # OpenClaw process detection (sysinfo)      ✅ Phase 2
├── guards/
│   ├── mod.rs
│   ├── fs_guard.rs      # Filesystem Guard                          ✅ Phase 2
│   ├── cdp_proxy.rs     # CDP Proxy (browser guard)                 ✅ Phase 2
│   ├── net_guard.rs     # Network Egress Monitor                    ✅ Phase 3
│   └── cmd_guard.rs     # Command Interceptor                       ✅ Phase 3
├── alerting/
│   ├── mod.rs
│   ├── engine.rs        # Central alert dispatcher                  ✅ Phase 1+4
│   ├── slack.rs         # Slack webhook backend                     ✅ Phase 4
│   ├── macos_notify.rs  # macOS native notifications               ✅ Phase 1
│   └── logger.rs        # JSON Lines structured logging             ✅ Phase 1
├── daemon.rs            # Module orchestration, signals             ✅ Phase 4
└── dashboard/
    ├── mod.rs
    └── server.rs        # axum HTTP server                          ✅ Phase 4
tests/
├── common/mod.rs        # Shared test helpers (TestEnv)
├── phase1_test.rs       # 24 tests — config, types, alerting, CLI
├── process_test.rs      # 9 tests — process detection
├── fs_guard_test.rs     # 23 tests — filesystem guard
├── cdp_proxy_test.rs    # 53 tests — CDP proxy
├── cmd_guard_test.rs    # 28 tests — command guard
├── net_guard_test.rs    # 21 tests — network guard
├── cli_test_command_test.rs # 15 tests — CLI test command
├── event_buffer_test.rs # 8 tests — event buffer
├── slack_test.rs        # 20 tests — Slack notifier
├── alerting_engine_test.rs # 6 tests — alerting engine integration
├── daemon_test.rs       # 12 tests — daemon orchestration
├── dashboard_test.rs    # 13 tests — dashboard HTTP endpoints
├── cli_status_test.rs   # 5 tests — CLI status command
└── integration_test.rs  # ⏳ Phase 5
```

## Implementation Build Order

The spec prescribes a phased approach:

1. **Phase 1 — Foundations**: Cargo.toml + deps, config.rs (YAML), types.rs, main.rs (clap CLI), alerting (logger → macos_notify → engine)
2. **Phase 2 — Core Guards** (parallel): process.rs, fs_guard.rs, cdp_proxy.rs (HTTP discovery → WS relay → JSON filtering → URL tracking → content inspection)
3. **Phase 3 — Additional Guards**: net_guard.rs (lsof polling), cmd_guard.rs (process tree polling)
4. **Phase 4 — Polish**: daemon.rs (signals), dashboard server, status/test CLI commands, Slack webhook
5. **Phase 5 — Packaging**: Makefile, launchd plist, GitHub release

## Key Technical Decisions

- **Async runtime**: tokio (multi-threaded)
- **Error handling**: `anyhow` for top-level/main, `thiserror` for typed module errors
- **Config**: YAML at `~/.counterclaw/config.yaml`, supports 3 modes: `monitor` (log only), `enforce` (block + kill), `paranoid` (block everything not explicitly allowed)
- **CDP Proxy mechanics**: Rewrites `webSocketDebuggerUrl` in HTTP discovery to redirect agent through proxy. Maintains `CdpSessionState` with `current_url` for domain-aware command filtering. Returns synthetic JSON-RPC error responses when blocking.
- **Process detection (MVP)**: Heuristic via `sysinfo` crate — no exact PID attribution from filesystem events. Future: macOS Endpoint Security Framework.
- **Notifications**: macOS native via `osascript` (no external crate needed)
- **Logging**: JSON Lines format with rotation, structured `SecurityEvent` records

## Development Methodology: Security-First TDD (Red-Green-Refactor)

CounterClaw is a security tool. Every rule it enforces MUST be proven by tests.

### The Iron Law

```
NO PRODUCTION CODE WITHOUT A FAILING TEST FIRST
```

If code was written before its test — delete it, start over. No exceptions.
If a test passes immediately — the test is wrong. Fix it until it fails for the right reason.

### Strict Workflow: Every Feature, Every Bug Fix

Each feature or fix follows this exact cycle. No step is optional.

#### Step 1: RED — Write ONE failing test

- Write a single test that describes the desired behavior
- Test name = sentence describing what should happen (e.g., `blocks_access_to_ssh_directory`)
- One behavior per test. If the name contains "and", split it
- Prefer real code over mocks. Mocks only when unavoidable (network, OS notifications)

```bash
cargo test <test_name>    # MUST fail — verify the failure message is correct
```

In Rust, RED can mean:
- Compilation error (function/struct doesn't exist yet) — valid RED
- Assertion failure (logic not implemented) — valid RED
- Test passes immediately — INVALID, fix the test

#### Step 2: Verify RED

**MANDATORY. Never skip.**

Confirm:
- The test fails (not just errors on unrelated syntax)
- The failure message matches expectations (missing function, wrong return value, etc.)
- It fails because the feature is missing, not because of a typo

#### Step 3: GREEN — Write the MINIMUM code to pass

- Implement the simplest thing that makes the test pass
- No extra features, no "while I'm here" improvements
- No refactoring other code
- No anticipating future requirements (YAGNI)

```bash
cargo test <test_name>    # MUST pass
cargo test                # ALL tests MUST still pass (no regressions)
```

#### Step 4: Verify GREEN

**MANDATORY. Never skip.**

Confirm:
- The new test passes
- All existing tests still pass
- No new warnings from clippy

#### Step 5: REFACTOR — Clean up, tests stay green

After GREEN only:
- Remove duplication (DRY)
- Improve names for clarity
- Extract shared helpers to `tests/common/mod.rs`
- Simplify logic (KISS)
- Ensure each struct/function has one responsibility (SRP)

```bash
cargo test                     # Still all green after refactor
cargo clippy -- -D warnings    # Still clean
```

#### Step 6: Security Layer — Adversarial tests

For every security rule, after the happy path works, add:

- **Positive test**: the rule correctly blocks/detects the threat
- **Negative test**: legitimate actions are NOT blocked (no false positives)
- **Bypass test**: evasion attempts fail (path traversal `../`, encoding tricks, case variations, glob edge cases)
- **Edge case test**: empty input, very long input, unicode, null bytes, special characters

Each adversarial test follows the same RED → verify → GREEN → verify cycle.

#### Step 7: Full suite verification

```bash
cargo fmt --check              # Formatting
cargo clippy -- -D warnings    # Lints
cargo test                     # All tests pass
cargo test -- --ignored        # Slow/integration tests (if any)
```

### Cycle summary

```
RED (write 1 failing test)
  → Verify RED (confirm correct failure)
    → GREEN (minimum code to pass)
      → Verify GREEN (all tests pass)
        → REFACTOR (clean up, stay green)
          → Security tests (bypass/edge cases, each via RED→GREEN)
            → Full suite verification
              → Next feature (back to RED)
```

### What MUST be tested

For every security rule (path blocking, domain filtering, command interception, etc.):

| Test type | Purpose | Example |
|-----------|---------|---------|
| Positive | Rule blocks the threat | `blocks_access_to_ssh_directory` |
| Negative | Legitimate use is allowed | `allows_access_to_user_documents` |
| Bypass | Evasion fails | `blocks_ssh_via_path_traversal` |
| Edge case | Weird input handled | `handles_empty_path_gracefully` |

### Test categories

```
tests/
├── common/mod.rs            # Shared helpers: temp dirs, mock configs, event assertions
├── phase1_test.rs           # Config, types, alerting
├── fs_guard_test.rs         # Filesystem guard (Phase 2)
├── cdp_proxy_test.rs        # CDP Proxy (Phase 2)
├── net_guard_test.rs        # Network guard (Phase 3)
├── cmd_guard_test.rs        # Command guard (Phase 3)
└── integration_test.rs      # End-to-end scenarios
```

### Test isolation rules

- Each test gets its own temp directory — NO shared filesystem state
- Tests NEVER touch `~/.counterclaw/` (the real config) — always use temp paths
- Tests NEVER make real network calls — mock or loopback only
- Tests NEVER spawn real osascript notifications

### Build security guarantees

- `#![deny(unsafe_code)]` — zero unsafe Rust in the entire codebase
- `#![deny(clippy::all)]` — zero clippy warnings
- Strict clippy lints for security: no unwrap in production code, no panic in library code
- `cargo test` must pass before any commit
- `cargo clippy -- -D warnings` must pass before any commit

### Red flags — STOP and start over

If any of these happen, delete the production code and restart from RED:

- Code written before its test
- Test passes immediately (not a real test)
- Can't explain why the test failed
- "I'll add tests later"
- "Just this once without TDD"
- "I already manually tested it"
- Keeping pre-TDD code "as reference"

## Design Principles (Rust-adapted)

### SOLID

- **Single Responsibility**: Each module, struct, and function has ONE reason to change. A guard watches ONE category of threat. The alerting engine dispatches — it doesn't decide what's a threat.
- **Open/Closed**: Use traits for extension. The `Guard` trait lets us add new guards without modifying the daemon. New alerting backends implement a common interface.
- **Liskov Substitution**: Any `Guard` implementation is interchangeable in the daemon's startup sequence. Tests can substitute mock guards.
- **Interface Segregation**: Small, focused traits. Don't force a guard to implement notification logic. Don't force an alerting backend to know about filesystem paths.
- **Dependency Inversion**: Modules depend on traits and channel types (`mpsc::Sender<SecurityEvent>`), not on concrete implementations. The daemon doesn't know about FS Guard internals.

### KISS

- Prefer `match` and `if let` over complex trait hierarchies
- Prefer simple functions over deep abstraction layers
- If a design feels over-engineered, it probably is — simplify
- Three similar lines of code is better than a premature abstraction

### DRY

- Extract shared test setup into `tests/common/mod.rs`
- Shared types live in `types.rs`, not duplicated across modules
- Config validation logic lives in `config.rs`, not in each guard
- If the same pattern appears 3+ times, extract it

### Secure by Default

- `#![deny(unsafe_code)]` — no unsafe, period
- No `.unwrap()` in production code — use `?` or proper error handling
- Validate all external input at system boundaries (config parsing, CDP messages, network data)
- Internal module-to-module communication via typed channels — no raw strings
- Default to deny: if unsure whether to allow something, block it

## Code Conventions

- Zero clippy warnings (`#![deny(clippy::all)]`)
- `#![deny(unsafe_code)]` — no unsafe Rust
- Doc comments (`///`) on all public functions
- Rust 2021 edition, minimum toolchain 1.75+
- Inter-module communication exclusively via `mpsc::channel<SecurityEvent>`
- CDP Proxy is the highest-priority module — allocate the most attention there
- No `.unwrap()` in production code — use `?` or proper error handling
- Tests use `#[test]` for unit tests, `tests/` directory for integration tests

## MVP Simplifications

These are explicitly deferred per spec:
- Dashboard: JSON API only, no HTML frontend
- `require_approval` mode: block + notify only, no interactive approval flow
- Net Guard `pf_rules` enforcement: deferred (needs root)
- Cmd Guard `es_framework` monitoring: deferred (needs Apple entitlement)
- Process attribution: heuristic only (not exact PID)
