//! PollingMonitor — détection de processus par polling sysinfo (fallback Linux).
//!
//! Extrait de la logique existante de CmdGuard.
//! Limitation connue : rate les processus éphémères (< poll_interval).

use crate::guards::process_monitor::{DetectedProcess, ProcessMonitor};
use crate::process::matches_process_patterns;
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Moniteur de processus par polling (fallback pour plateformes sans kqueue).
pub struct PollingMonitor {
    watch_patterns: Vec<String>,
    poll_interval: Duration,
}

impl PollingMonitor {
    /// Crée un nouveau moniteur polling avec les patterns et l'intervalle spécifiés.
    pub fn new(patterns: Vec<String>, poll_interval: Duration) -> Self {
        Self {
            watch_patterns: patterns,
            poll_interval,
        }
    }
}

#[async_trait::async_trait]
impl ProcessMonitor for PollingMonitor {
    async fn start(
        &self,
        tx: mpsc::Sender<DetectedProcess>,
        token: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut scanner = crate::process::ProcessScanner::new();
        let mut seen_pids: HashSet<u32> = HashSet::new();
        let patterns = self.watch_patterns.clone();
        let interval = self.poll_interval;

        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(interval) => {
                    scanner.refresh();
                    let all_procs = scanner.scan_all();

                    // Prune dead PIDs
                    let active_pids: HashSet<u32> = all_procs.iter().map(|p| p.pid).collect();
                    seen_pids.retain(|pid| active_pids.contains(pid));

                    for proc in &all_procs {
                        if seen_pids.contains(&proc.pid) {
                            continue;
                        }

                        // macOS fallback: use name when cmd is empty
                        let check_str = if proc.cmd.trim().is_empty() {
                            &proc.name
                        } else {
                            &proc.cmd
                        };

                        if matches_process_patterns(&proc.name, check_str, &patterns) {
                            seen_pids.insert(proc.pid);
                            let detected = DetectedProcess {
                                pid: proc.pid,
                                name: proc.name.clone(),
                                cmd: if proc.cmd.is_empty() {
                                    vec![proc.name.clone()]
                                } else {
                                    proc.cmd.split_whitespace().map(String::from).collect()
                                },
                            };
                            let _ = tx.try_send(detected);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
