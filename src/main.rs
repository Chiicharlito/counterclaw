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
use counterclaw::types::{ActionTaken, GuardModule, SecurityEvent, Severity};
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
    Status,

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
        Commands::Status => {
            println!("Status command will be available in a future version.");
        }
        Commands::Logs { .. } => {
            println!("Logs command will be available in a future version.");
        }
        Commands::Test { .. } => {
            println!("Test command will be available in a future version.");
        }
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

    // 3. Créer le canal mpsc pour les événements
    let (alert_tx, alert_rx) = mpsc::channel::<SecurityEvent>(1000);

    // 4. Lancer le moteur d'alerting dans sa propre tâche
    let engine = AlertingEngine::new(&app_config.alerting);
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
