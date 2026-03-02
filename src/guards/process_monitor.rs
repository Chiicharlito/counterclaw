//! ProcessMonitor trait — abstraction pour la détection de processus.
//!
//! Deux implémentations :
//! - **KqueueMonitor** (macOS) : événements kqueue EVFILT_PROC en temps réel
//! - **PollingMonitor** (Linux/fallback) : polling via sysinfo

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Informations sur un processus détecté.
#[derive(Debug, Clone)]
pub struct DetectedProcess {
    pub pid: u32,
    pub name: String,
    pub cmd: Vec<String>,
}

/// Trait d'abstraction pour la détection de processus.
#[async_trait::async_trait]
pub trait ProcessMonitor: Send + Sync {
    /// Démarre la surveillance et envoie les processus détectés sur le channel.
    /// Bloque jusqu'à ce que le CancellationToken soit annulé.
    async fn start(
        &self,
        tx: mpsc::Sender<DetectedProcess>,
        token: CancellationToken,
    ) -> anyhow::Result<()>;
}
