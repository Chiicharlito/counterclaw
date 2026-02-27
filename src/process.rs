//! Détection et gestion des processus OpenClaw.
//!
//! Deux couches :
//! 1. **Logique pure** : `matches_process_patterns()` compare un nom/commande
//!    de processus contre une liste de patterns (exact ou regex). Zéro IO.
//! 2. **Couche système** : `ProcessScanner` utilise `sysinfo` pour lister
//!    les processus réels. `kill_process()` envoie SIGKILL.

use regex::Regex;
use sysinfo::System;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Informations sur un processus détecté.
/// Distinct de `types::ProcessInfo` qui est le format d'événement sérialisable.
/// Celui-ci est utilisé pour le scanning interne.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmd: String,
    pub parent_pid: Option<u32>,
}

// ---------------------------------------------------------------------------
// Logique pure — pattern matching
// ---------------------------------------------------------------------------

/// Vérifie si un processus (nom + ligne de commande) correspond à au moins
/// un pattern dans la liste.
///
/// Chaque pattern est d'abord testé comme match exact sur le nom,
/// puis comme regex sur la ligne de commande complète.
/// Les regex invalides sont silencieusement ignorées.
pub fn matches_process_patterns(name: &str, cmd: &str, patterns: &[String]) -> bool {
    if name.is_empty() && cmd.is_empty() {
        return false;
    }

    for pattern in patterns {
        // Match exact sur le nom
        if !name.is_empty() && pattern == name {
            return true;
        }

        // Match regex sur la ligne de commande complète
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(cmd) {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Couche système — scanning via sysinfo
// ---------------------------------------------------------------------------

/// Scanner de processus utilisant `sysinfo`.
pub struct ProcessScanner {
    system: System,
}

impl Default for ProcessScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessScanner {
    /// Crée un nouveau scanner avec la liste de processus rafraîchie.
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        Self { system }
    }

    /// Rafraîchit la liste des processus.
    pub fn refresh(&mut self) {
        self.system
            .refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    }

    /// Retourne tous les processus visibles sous forme de `ProcessInfo`.
    pub fn scan_all(&self) -> Vec<ProcessInfo> {
        self.system
            .processes()
            .iter()
            .map(|(pid, proc)| ProcessInfo {
                pid: pid.as_u32(),
                name: proc.name().to_string_lossy().to_string(),
                cmd: proc
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" "),
                parent_pid: proc.parent().map(|p| p.as_u32()),
            })
            .collect()
    }

    /// Trouve les processus dont le nom ou la commande matche les patterns.
    pub fn find_matching(&self, patterns: &[String]) -> Vec<ProcessInfo> {
        self.scan_all()
            .into_iter()
            .filter(|p| matches_process_patterns(&p.name, &p.cmd, patterns))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Kill process
// ---------------------------------------------------------------------------

/// Envoie SIGKILL à un processus par PID.
/// Retourne Ok(true) si le signal a été envoyé, Ok(false) si le process
/// n'a pas été trouvé, Err si une erreur système survient.
pub fn kill_process(pid: u32) -> anyhow::Result<bool> {
    let mut system = System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let sysinfo_pid = sysinfo::Pid::from_u32(pid);
    if let Some(process) = system.process(sysinfo_pid) {
        process.kill();
        Ok(true)
    } else {
        Ok(false)
    }
}
