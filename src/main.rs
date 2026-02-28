// ===== Build security: zero tolerance =====
#![deny(unsafe_code)]
#![deny(clippy::all)]

//! CounterClaw — AI Agent Guardian
//!
//! Daemon OS-level qui protège les machines contre l'exfiltration
//! de données par des agents IA autonomes.

use clap::{Parser, Subcommand};
use counterclaw::alerting::engine::AlertingEngine;
use counterclaw::config::{self, default_config_path, expand_tilde};
use counterclaw::daemon;
use counterclaw::guards::cdp_proxy::DomainMatcher;
use counterclaw::guards::cmd_guard::{CommandMatcher, MatchType};
use counterclaw::guards::fs_guard::{PathMatcher, PathVerdict};
use counterclaw::types::{ActionTaken, EventBuffer, GuardModule, SecurityEvent, Severity};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// CLI — définition des commandes
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "counterclaw")]
#[command(about = "CounterClaw — AI Agent Guardian")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start CounterClaw in foreground
    Start {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Manage the background daemon
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Show current status
    Status {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Follow logs
    Logs {
        #[arg(long)]
        follow: bool,
        #[arg(long)]
        module: Option<String>,
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        last: Option<String>,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Test rules against specific inputs
    Test {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
        #[command(subcommand)]
        target: TestTarget,
    },

    /// Open the web dashboard
    Dashboard,
}

#[derive(Subcommand)]
pub enum DaemonAction {
    /// Start daemon in background
    Start,
    /// Stop the daemon
    Stop,
    /// Restart the daemon
    Restart,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Validate current config
    Check {
        /// Path to config file
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Generate default config
    Init,
}

#[derive(Subcommand)]
pub enum TestTarget {
    /// Test a file path against FS rules
    Path { path: String },
    /// Test a domain against CDP rules
    Domain { domain: String },
    /// Test a command against CMD rules
    Command { command: String },
}

// ---------------------------------------------------------------------------
// Point d'entrée
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config } => cmd_start(config).await,
        Commands::Config { action } => cmd_config(action),
        Commands::Daemon { .. } => {
            println!("Daemon mode will be available in a future version.");
        }
        Commands::Status { config } => cmd_status(config).await,
        Commands::Logs { .. } => {
            println!("Logs command will be available in a future version.");
        }
        Commands::Test { config, target } => cmd_test(config, target),
        Commands::Dashboard => {
            println!("Dashboard will be available in a future version.");
        }
    }
}

// ---------------------------------------------------------------------------
// Commande : config init / config check
// ---------------------------------------------------------------------------

fn cmd_config(action: ConfigAction) {
    match action {
        ConfigAction::Init => {
            match config::init_config() {
                Ok(path) => {
                    if path.exists() {
                        // Le fichier existait déjà ou vient d'être créé
                        println!("Config file ready at: {}", path.display());
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        ConfigAction::Check { config: path } => {
            let config_path = path
                .map(|p| expand_tilde(&p))
                .unwrap_or_else(default_config_path);

            match config::check_config(&config_path) {
                Ok(_config) => {
                    println!("Config is valid: {}", config_path.display());
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Commande : test — teste une regle contre un input specifique
// ---------------------------------------------------------------------------

/// Charge la config et teste un chemin, domaine ou commande contre les regles.
/// Exit code 0 = autorise, exit code 1 = bloque.
fn cmd_test(config_path: Option<String>, target: TestTarget) {
    // Charger la config (meme pattern que cmd_config Check)
    let path = config_path
        .map(|p| expand_tilde(&p))
        .unwrap_or_else(default_config_path);

    let app_config = match config::check_config(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match target {
        TestTarget::Path { path: test_path } => {
            let matcher = PathMatcher::new(
                app_config.fs_guard.blocked_paths.clone(),
                app_config.fs_guard.read_only_paths.clone(),
                app_config.fs_guard.allowed_paths.clone(),
            );
            let expanded = expand_tilde(&test_path);
            let verdict = matcher.check(&expanded);
            match verdict {
                PathVerdict::Blocked => {
                    println!("BLOCKED — path is in blocked_paths");
                    std::process::exit(1);
                }
                PathVerdict::ReadOnly => {
                    println!("READ_ONLY — path is in read_only_paths (writes blocked)");
                    std::process::exit(1);
                }
                PathVerdict::Allowed => {
                    println!("ALLOWED — path is explicitly allowed");
                }
                PathVerdict::Unmatched => {
                    println!("UNMATCHED — path not covered by any rule");
                }
            }
        }
        TestTarget::Domain { domain } => {
            let matcher = DomainMatcher::new(&app_config.cdp_proxy.domains);
            let verdict = matcher.check(&domain);
            match verdict {
                counterclaw::guards::cdp_proxy::DomainVerdict::Blocked => {
                    println!("BLOCKED — domain is in blocked list");
                    std::process::exit(1);
                }
                counterclaw::guards::cdp_proxy::DomainVerdict::RequireApproval => {
                    println!("REQUIRE_APPROVAL — domain needs approval");
                }
                counterclaw::guards::cdp_proxy::DomainVerdict::Allowed => {
                    println!("ALLOWED — domain is permitted");
                }
            }
        }
        TestTarget::Command { command } => {
            let matcher = CommandMatcher::new(&app_config.cmd_guard);
            match matcher.match_command(&command) {
                Some(verdict) => match verdict.match_type {
                    MatchType::Blacklisted => {
                        println!("BLOCKED [{}] — {}", verdict.severity, verdict.description);
                        std::process::exit(1);
                    }
                    MatchType::RequiresApproval => {
                        println!("REQUIRE_APPROVAL — {}", verdict.description);
                    }
                },
                None => {
                    println!("ALLOWED — command matches no rules");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Commande : status — affiche l'état du daemon
// ---------------------------------------------------------------------------

/// Vérifie si CounterClaw tourne et affiche son état.
/// Exit code 0 = running, exit code 1 = not running ou erreur.
async fn cmd_status(config_path: Option<String>) {
    // 1. Charger la config pour trouver le PID file
    let path = config_path
        .map(|p| expand_tilde(&p))
        .unwrap_or_else(default_config_path);

    let app_config = match config::check_config(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let pid_path = expand_tilde(&app_config.general.pid_file);

    // 2. Lire le PID file
    let pid = match daemon::read_pid_file(&pid_path) {
        Some(p) => p,
        None => {
            println!("CounterClaw is not running (no PID file)");
            std::process::exit(1);
        }
    };

    // 3. Vérifier si le process existe
    if !process_exists(pid) {
        println!("CounterClaw is not running (stale PID file, pid={})", pid);
        std::process::exit(1);
    }

    // 4. Appeler le dashboard pour obtenir le statut
    let url = format!(
        "http://{}:{}/api/status",
        app_config.dashboard.bind_address, app_config.dashboard.port
    );

    match reqwest::get(&url).await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<serde_json::Value>().await {
                    Ok(json) => {
                        println!("CounterClaw is running (pid={})", pid);
                        if let Some(mode) = json.get("mode").and_then(|v| v.as_str()) {
                            println!("Mode: {}", mode);
                        }
                        if let Some(uptime) =
                            json.get("daemon_uptime_seconds").and_then(|v| v.as_i64())
                        {
                            println!("Uptime: {}s", uptime);
                        }
                        if let Some(guards) = json.get("guards").and_then(|v| v.as_array()) {
                            println!("Guards:");
                            for g in guards {
                                let name = g.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                                let running =
                                    g.get("running").and_then(|v| v.as_bool()).unwrap_or(false);
                                let status = if running { "running" } else { "stopped" };
                                println!("  {} — {}", name, status);
                            }
                        }
                    }
                    Err(_) => {
                        println!(
                            "CounterClaw is running (pid={}) but dashboard returned invalid data",
                            pid
                        );
                    }
                }
            } else {
                println!("CounterClaw dashboard unreachable (HTTP {})", resp.status());
                std::process::exit(1);
            }
        }
        Err(_) => {
            println!("CounterClaw dashboard unreachable (connection refused or not responding)");
            std::process::exit(1);
        }
    }
}

/// Vérifie si un process avec ce PID existe.
fn process_exists(pid: u32) -> bool {
    let s = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::new().with_processes(sysinfo::ProcessRefreshKind::new()),
    );
    s.process(sysinfo::Pid::from_u32(pid)).is_some()
}

// ---------------------------------------------------------------------------
// Commande : start — lance CounterClaw en foreground
// ---------------------------------------------------------------------------

async fn cmd_start(config_path: Option<String>) {
    // 1. Charger la config
    let path = config_path
        .map(|p| expand_tilde(&p))
        .unwrap_or_else(default_config_path);

    let app_config = match config::check_config(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // 2. Bannière de démarrage
    let mode = app_config.operation_mode();
    println!("CounterClaw v{} starting...", env!("CARGO_PKG_VERSION"));
    println!("Config loaded from: {}", path.display());
    println!("Mode: {}", mode);
    println!();

    // 3. Créer le canal mpsc et le buffer d'événements
    let (alert_tx, alert_rx) = mpsc::channel::<SecurityEvent>(1000);
    let event_buffer = Arc::new(RwLock::new(EventBuffer::new(10000)));

    // 4. Lancer le moteur d'alerting dans sa propre tâche
    let engine = AlertingEngine::new(&app_config.alerting, event_buffer);
    let engine_handle = tokio::spawn(async move {
        engine.run(alert_rx).await;
    });

    // 5. Envoyer un événement de démarrage
    let startup_event = SecurityEvent::new(
        GuardModule::System,
        Severity::Info,
        ActionTaken::Logged,
        format!("CounterClaw started in {} mode", mode),
    );
    let _ = alert_tx.send(startup_event).await;

    println!("Waiting for activity... (Press Ctrl+C to stop)");
    println!();

    // 6. Attendre Ctrl+C
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            println!();
            println!("Shutting down...");
        }
        Err(e) => {
            eprintln!("Failed to listen for Ctrl+C: {}", e);
        }
    }

    // 7. Graceful shutdown : dropper le sender ferme le canal,
    //    ce qui fait sortir le engine de sa boucle recv().
    drop(alert_tx);
    let _ = engine_handle.await;

    println!("CounterClaw stopped.");
}
