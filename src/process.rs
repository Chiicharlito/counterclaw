//! Detection et gestion des processus OpenClaw.
//!
//! Deux couches :
//! 1. **Logique pure** : `matches_process_patterns()` compare un nom/commande
//!    de processus contre une liste de patterns (exact ou regex). Zero IO.
//! 2. **Couche systeme** : `ProcessScanner` utilise `sysinfo` pour lister
//!    les processus reels. `kill_process()` envoie SIGKILL.

use regex::Regex;
use sysinfo::System;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Informations sur un processus detecte.
/// Distinct de `types::ProcessInfo` qui est le format d'evenement serialisable.
/// Celui-ci est utilise pour le scanning interne.
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

/// Verifie si un processus (nom + ligne de commande) correspond a au moins
/// un pattern dans la liste.
///
/// Chaque pattern est d'abord teste comme match exact sur le nom,
/// puis comme regex sur la ligne de commande complete.
/// Les regex invalides sont silencieusement ignorees.
pub fn matches_process_patterns(name: &str, cmd: &str, patterns: &[String]) -> bool {
    if name.is_empty() && cmd.is_empty() {
        return false;
    }

    for pattern in patterns {
        // Match exact sur le nom
        if !name.is_empty() && pattern == name {
            return true;
        }

        // Match regex sur la ligne de commande complete
        if let Ok(re) = Regex::new(pattern) {
            if re.is_match(cmd) {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// argv[0] vs binary path mismatch detection
// ---------------------------------------------------------------------------

/// Verifie si argv[0] (le nom du processus) ne correspond pas au chemin
/// reel du binaire dans la ligne de commande.
///
/// Cela peut indiquer un processus qui tente de se deguiser (spoofing).
/// Par exemple, un processus qui se fait passer pour "bash" alors que
/// son binaire reel est "/tmp/malware".
///
/// Retourne true si une divergence est detectee (potentiel spoofing).
/// Retourne false si les noms correspondent, ou si la commande est vide
/// ou ne contient pas d'information exploitable.
/// V10: Activated — no longer dead_code.
pub fn check_argv0_mismatch(name: &str, cmd: &str) -> bool {
    // If either is empty, we can't compare
    if name.is_empty() || cmd.is_empty() {
        return false;
    }

    // Extract the first argument from cmd (the binary path)
    let first_arg = cmd.split_whitespace().next();
    let first_arg = match first_arg {
        Some(arg) => arg,
        None => return false,
    };

    // Get the filename from the binary path
    let binary_filename = std::path::Path::new(first_arg)
        .file_name()
        .and_then(|n| n.to_str());

    let binary_filename = match binary_filename {
        Some(f) => f,
        None => return false,
    };

    // Compare: if the process name doesn't match the binary filename,
    // this is a potential spoofing indicator
    name != binary_filename
}

// ---------------------------------------------------------------------------
// Couche systeme — scanning via sysinfo
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
    /// Cree un nouveau scanner avec la liste de processus rafraichie.
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        Self { system }
    }

    /// Rafraichit la liste des processus.
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

    /// Recherche un processus par PID et retourne ses informations complètes.
    ///
    /// Utilise le cache sysinfo déjà rafraîchi (appeler `refresh()` d'abord).
    /// Retourne None si le PID n'existe pas.
    pub fn get_by_pid(&self, pid: u32) -> Option<ProcessInfo> {
        let sysinfo_pid = sysinfo::Pid::from_u32(pid);
        self.system.process(sysinfo_pid).map(|proc| ProcessInfo {
            pid,
            name: proc.name().to_string_lossy().to_string(),
            cmd: proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
            parent_pid: proc.parent().map(|p| p.as_u32()),
        })
    }

    /// Trouve les processus dont le nom ou la commande matche les patterns.
    pub fn find_matching(&self, patterns: &[String]) -> Vec<ProcessInfo> {
        self.scan_all()
            .into_iter()
            .filter(|p| matches_process_patterns(&p.name, &p.cmd, patterns))
            .collect()
    }

    /// Vérifie si au moins un processus actif matche les patterns surveillés.
    /// Effectue un refresh avant de scanner.
    /// Sur macOS, utilise le nom comme fallback quand cmd() est vide.
    pub fn has_watched_processes(&mut self, patterns: &[String]) -> bool {
        self.refresh();
        self.system.processes().values().any(|proc| {
            let name = proc.name().to_string_lossy().to_string();
            let cmd = proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            // macOS fallback: when cmd is empty, use name as the check string
            let check_str = if cmd.trim().is_empty() { &name } else { &cmd };
            matches_process_patterns(&name, check_str, patterns)
        })
    }

    /// Retourne les PIDs des processus qui matchent les patterns surveillés.
    /// Effectue un refresh avant de scanner.
    /// Sur macOS, utilise le nom comme fallback quand cmd() est vide.
    pub fn find_watched_pids(&mut self, patterns: &[String]) -> Vec<u32> {
        self.refresh();
        self.system
            .processes()
            .iter()
            .filter_map(|(pid, proc)| {
                let name = proc.name().to_string_lossy().to_string();
                let cmd = proc
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ");
                // macOS fallback: when cmd is empty, use name as the check string
                let check_str = if cmd.trim().is_empty() { &name } else { &cmd };
                if matches_process_patterns(&name, check_str, patterns) {
                    Some(pid.as_u32())
                } else {
                    None
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Kill process
// ---------------------------------------------------------------------------

/// Envoie SIGKILL a un processus par PID.
/// Retourne Ok(true) si le signal a ete envoye, Ok(false) si le process
/// n'a pas ete trouve, Err si une erreur systeme survient.
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
