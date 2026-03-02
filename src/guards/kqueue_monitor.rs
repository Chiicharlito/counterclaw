//! KqueueMonitor — détection de processus en temps réel via kqueue (macOS).
//!
//! Approche hybride : scan rapide des PIDs (50ms) + kqueue EVFILT_PROC
//! pour capturer les exec en temps réel sur les PIDs découverts.
//! NOTE_TRACK peut ne pas être disponible (SIP sur macOS moderne).
//! Fonctionne sans root — surveille les processus du même UID.

#[cfg(target_os = "macos")]
use crate::guards::process_monitor::{DetectedProcess, ProcessMonitor};
#[cfg(target_os = "macos")]
use crate::process::matches_process_patterns;
#[cfg(target_os = "macos")]
use tokio::sync::mpsc;
#[cfg(target_os = "macos")]
use tokio_util::sync::CancellationToken;

/// Moniteur de processus basé sur kqueue (macOS uniquement).
///
/// Approche hybride : scan périodique des PIDs (50ms) + kqueue EVFILT_PROC
/// pour détection temps réel des exec. Supérieur au polling pur (500ms+)
/// mais limité par SIP pour les processus <50ms sans NOTE_TRACK.
#[cfg(target_os = "macos")]
pub struct KqueueMonitor {
    watch_patterns: Vec<String>,
}

#[cfg(target_os = "macos")]
impl KqueueMonitor {
    /// Crée un nouveau moniteur kqueue avec les patterns de processus à surveiller.
    pub fn new(patterns: Vec<String>) -> Self {
        Self {
            watch_patterns: patterns,
        }
    }

    /// Lit le nom et la ligne de commande d'un processus par PID.
    fn read_process_info(pid: u32) -> Option<(String, Vec<String>)> {
        let mut system = sysinfo::System::new();
        system.refresh_processes(
            sysinfo::ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]),
            true,
        );

        let sysinfo_pid = sysinfo::Pid::from_u32(pid);
        system.process(sysinfo_pid).map(|proc| {
            let name = proc.name().to_string_lossy().to_string();
            let cmd: Vec<String> = proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            (name, cmd)
        })
    }

    /// Probe which EVFILT_PROC flags are supported on this system.
    /// NOTE_TRACK may not be available due to SIP on macOS.
    #[cfg(target_os = "macos")]
    fn probe_supported_flags(kq: &nix::sys::event::Kqueue) -> nix::sys::event::FilterFlag {
        use nix::libc;
        use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent};

        let zero_timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let own_pid = std::process::id() as usize;
        let del = KEvent::new(
            own_pid,
            EventFilter::EVFILT_PROC,
            EventFlag::EV_DELETE,
            FilterFlag::empty(),
            0,
            0,
        );

        // Try full flags first (with NOTE_TRACK)
        let full_flags = FilterFlag::NOTE_FORK
            | FilterFlag::NOTE_EXEC
            | FilterFlag::NOTE_EXIT
            | FilterFlag::NOTE_TRACK;

        let test_event = KEvent::new(
            own_pid,
            EventFilter::EVFILT_PROC,
            EventFlag::EV_ADD | EventFlag::EV_ENABLE,
            full_flags,
            0,
            0,
        );

        let mut result_buf = vec![
            KEvent::new(
                0,
                EventFilter::EVFILT_PROC,
                EventFlag::empty(),
                FilterFlag::empty(),
                0,
                0,
            );
            1
        ];

        let full_works = match kq.kevent(&[test_event], &mut result_buf, Some(zero_timeout)) {
            Ok(0) => true,
            Ok(_) => !result_buf[0].flags().contains(EventFlag::EV_ERROR),
            Err(_) => false,
        };

        if full_works {
            let _ = kq.kevent(&[del], &mut [], Some(zero_timeout));
            return full_flags;
        }

        // Fallback: try without NOTE_TRACK
        let _ = kq.kevent(&[del], &mut [], Some(zero_timeout));
        let basic_flags = FilterFlag::NOTE_FORK | FilterFlag::NOTE_EXEC | FilterFlag::NOTE_EXIT;

        let test2 = KEvent::new(
            own_pid,
            EventFilter::EVFILT_PROC,
            EventFlag::EV_ADD | EventFlag::EV_ENABLE,
            basic_flags,
            0,
            0,
        );

        let basic_works = match kq.kevent(&[test2], &mut result_buf, Some(zero_timeout)) {
            Ok(0) => true,
            Ok(_) => !result_buf[0].flags().contains(EventFlag::EV_ERROR),
            Err(_) => false,
        };

        if basic_works {
            let _ = kq.kevent(&[del], &mut [], Some(zero_timeout));
            return basic_flags;
        }

        // EVFILT_PROC not supported at all
        let _ = kq.kevent(&[del], &mut [], Some(zero_timeout));
        tracing::warn!("kqueue EVFILT_PROC not supported on this system");
        FilterFlag::empty()
    }
}

#[cfg(target_os = "macos")]
#[async_trait::async_trait]
impl ProcessMonitor for KqueueMonitor {
    async fn start(
        &self,
        tx: mpsc::Sender<DetectedProcess>,
        token: CancellationToken,
    ) -> anyhow::Result<()> {
        use nix::libc;
        use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent, Kqueue};
        use std::collections::HashSet;

        let patterns = self.watch_patterns.clone();

        let (notify_tx, mut notify_rx) = mpsc::channel::<DetectedProcess>(256);
        let cancel_token = token.clone();

        let handle = tokio::task::spawn_blocking(move || {
            let kq = match Kqueue::new() {
                Ok(kq) => kq,
                Err(e) => {
                    tracing::error!("Failed to create kqueue: {}", e);
                    return;
                }
            };

            let proc_flags = Self::probe_supported_flags(&kq);
            if proc_flags.is_empty() {
                tracing::error!("kqueue EVFILT_PROC not supported — falling back to scan-only");
                // Fall through to scan-only mode (kqueue events won't fire but scans still work)
            }

            let mut tracked_pids: HashSet<usize> = HashSet::new();
            let mut eventlist = vec![
                KEvent::new(
                    0,
                    EventFilter::EVFILT_PROC,
                    EventFlag::empty(),
                    FilterFlag::empty(),
                    0,
                    0,
                );
                64
            ];

            let zero_timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };

            // Register on our own PID
            let own_pid = std::process::id() as usize;
            if !proc_flags.is_empty() {
                let own_event = KEvent::new(
                    own_pid,
                    EventFilter::EVFILT_PROC,
                    EventFlag::EV_ADD | EventFlag::EV_ENABLE,
                    proc_flags,
                    0,
                    0,
                );
                let _ = kq.kevent(&[own_event], &mut [], Some(zero_timeout));
            }
            tracked_pids.insert(own_pid);

            // Scan all current processes: register kqueue only (no pattern check).
            // Existing-process detection is handled by the caller (CmdGuard initial scan).
            let mut system = sysinfo::System::new();
            system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

            if !proc_flags.is_empty() {
                let mut changes: Vec<KEvent> = Vec::new();
                for pid in system.processes().keys() {
                    let pid_usize = pid.as_u32() as usize;
                    if pid_usize == 0 || tracked_pids.contains(&pid_usize) {
                        continue;
                    }
                    tracked_pids.insert(pid_usize);

                    changes.push(KEvent::new(
                        pid_usize,
                        EventFilter::EVFILT_PROC,
                        EventFlag::EV_ADD | EventFlag::EV_ENABLE,
                        proc_flags,
                        0,
                        0,
                    ));
                }
                if !changes.is_empty() {
                    let _ = kq.kevent(&changes, &mut [], Some(zero_timeout));
                }
            } else {
                // No kqueue — just track PIDs for the scan loop
                for pid in system.processes().keys() {
                    tracked_pids.insert(pid.as_u32() as usize);
                }
            }

            // Fast scan discovers newly spawned PIDs
            let scan_interval = std::time::Duration::from_millis(50);
            let mut last_scan = std::time::Instant::now();

            let kqueue_timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 50_000_000, // 50ms
            };

            loop {
                if cancel_token.is_cancelled() {
                    break;
                }

                // Fast periodic scan: discover new PIDs
                if last_scan.elapsed() >= scan_interval {
                    last_scan = std::time::Instant::now();
                    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

                    let mut new_changes: Vec<KEvent> = Vec::new();
                    for (pid, proc_info) in system.processes() {
                        let pid_usize = pid.as_u32() as usize;
                        if pid_usize == 0 || tracked_pids.contains(&pid_usize) {
                            continue;
                        }
                        tracked_pids.insert(pid_usize);

                        // Check newly discovered processes directly
                        // (they may have already exec'd and won't exec again)
                        let name = proc_info.name().to_string_lossy().to_string();
                        let cmd: Vec<String> = proc_info
                            .cmd()
                            .iter()
                            .map(|s| s.to_string_lossy().to_string())
                            .collect();
                        let cmd_joined = cmd.join(" ");
                        let check_str = if cmd_joined.trim().is_empty() {
                            &name
                        } else {
                            &cmd_joined
                        };

                        if matches_process_patterns(&name, check_str, &patterns) {
                            let detected = DetectedProcess {
                                pid: pid.as_u32(),
                                name: name.clone(),
                                cmd: if cmd.is_empty() {
                                    vec![name.clone()]
                                } else {
                                    cmd
                                },
                            };
                            if notify_tx.blocking_send(detected).is_err() {
                                return;
                            }
                        }

                        // Register kqueue for future exec events
                        if !proc_flags.is_empty() {
                            new_changes.push(KEvent::new(
                                pid_usize,
                                EventFilter::EVFILT_PROC,
                                EventFlag::EV_ADD | EventFlag::EV_ENABLE,
                                proc_flags,
                                0,
                                0,
                            ));
                        }
                    }
                    if !new_changes.is_empty() {
                        let _ = kq.kevent(&new_changes, &mut [], Some(zero_timeout));
                    }

                    // Limit tracked set size
                    if tracked_pids.len() > 50_000 {
                        tracked_pids.clear();
                        tracked_pids.insert(own_pid);
                    }
                }

                // Wait for kqueue events
                if !proc_flags.is_empty() {
                    let n = match kq.kevent(&[], &mut eventlist, Some(kqueue_timeout)) {
                        Ok(n) => n,
                        Err(nix::errno::Errno::EINTR) => continue,
                        Err(_) => continue,
                    };

                    for event in eventlist.iter().take(n) {
                        let event_pid = event.ident() as u32;
                        let fflags = event.fflags();

                        // NOTE_CHILD: child created (only with NOTE_TRACK)
                        if fflags.contains(FilterFlag::NOTE_CHILD)
                            && tracked_pids.insert(event_pid as usize)
                        {
                            let child_event = KEvent::new(
                                event_pid as usize,
                                EventFilter::EVFILT_PROC,
                                EventFlag::EV_ADD | EventFlag::EV_ENABLE | EventFlag::EV_ONESHOT,
                                proc_flags,
                                0,
                                0,
                            );
                            let _ = kq.kevent(&[child_event], &mut [], Some(zero_timeout));
                        }

                        // NOTE_FORK: A tracked process forked.
                        // Try to extract child PID from data field (macOS-specific).
                        if fflags.contains(FilterFlag::NOTE_FORK) {
                            let child_pid = event.data() as usize;
                            if child_pid > 0 && tracked_pids.insert(child_pid) {
                                let child_event = KEvent::new(
                                    child_pid,
                                    EventFilter::EVFILT_PROC,
                                    EventFlag::EV_ADD
                                        | EventFlag::EV_ENABLE
                                        | EventFlag::EV_ONESHOT,
                                    proc_flags,
                                    0,
                                    0,
                                );
                                let _ = kq.kevent(&[child_event], &mut [], Some(zero_timeout));
                            }
                        }

                        // NOTE_EXEC: Process called exec
                        if fflags.contains(FilterFlag::NOTE_EXEC) {
                            if let Some((name, cmd)) = Self::read_process_info(event_pid) {
                                let cmd_joined = cmd.join(" ");
                                let check_str = if cmd_joined.trim().is_empty() {
                                    &name
                                } else {
                                    &cmd_joined
                                };

                                if matches_process_patterns(&name, check_str, &patterns) {
                                    let detected = DetectedProcess {
                                        pid: event_pid,
                                        name,
                                        cmd,
                                    };
                                    if notify_tx.blocking_send(detected).is_err() {
                                        return;
                                    }
                                }
                            }

                            tracked_pids.remove(&(event_pid as usize));
                        }

                        // Clean up exited PIDs
                        if fflags.contains(FilterFlag::NOTE_EXIT) {
                            tracked_pids.remove(&(event_pid as usize));
                        }
                    }
                } else {
                    // No kqueue support — just scan (already done above)
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        });

        // Forward detections from blocking thread to caller
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    break;
                }
                result = notify_rx.recv() => {
                    match result {
                        Some(detected) => {
                            let _ = tx.try_send(detected);
                        }
                        None => break,
                    }
                }
            }
        }

        let _ = handle.await;
        Ok(())
    }
}
