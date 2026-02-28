//! Logger d'événements en JSON Lines (.jsonl).
//!
//! Chaque SecurityEvent est sérialisé en une ligne JSON et appendé
//! au fichier de log. La rotation se fait par taille : quand le fichier
//! dépasse la limite, il est renommé avec un suffixe numérique.

use crate::config::expand_tilde;
use crate::types::SecurityEvent;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// Logger d'événements vers un fichier JSON Lines.
pub struct EventLogger {
    path: PathBuf,
    max_size_bytes: u64,
    keep_files: u32,
}

impl EventLogger {
    /// Crée un nouveau logger.
    pub fn new(path: &str, max_size_mb: u64, keep_files: u32) -> Self {
        Self {
            path: expand_tilde(path),
            max_size_bytes: max_size_mb * 1024 * 1024,
            keep_files,
        }
    }

    /// Écrit un événement dans le fichier JSON Lines.
    /// Definit les permissions du repertoire a 0700 et du fichier a 0600.
    pub fn log(&self, event: &SecurityEvent) {
        // S'assurer que le répertoire parent existe
        if let Some(parent) = self.path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("[counterclaw] Failed to create log directory: {}", e);
                return;
            }
            // Set directory permissions to 0700 (owner-only access)
            Self::set_directory_permissions(parent);
        }

        // Rotation si le fichier est trop gros
        self.rotate_if_needed();

        // Sérialiser et écrire
        let line = match serde_json::to_string(event) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("[counterclaw] Failed to serialize event: {}", e);
                return;
            }
        };

        let result = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut file| {
                writeln!(file, "{}", line)?;
                // Set file permissions to 0600 (owner-only read/write)
                Self::set_log_file_permissions(&self.path);
                Ok(())
            });

        if let Err(e) = result {
            eprintln!(
                "[counterclaw] Failed to write to {}: {}",
                self.path.display(),
                e
            );
        }
    }

    /// Set file permissions to 0600 (owner read/write only).
    fn set_log_file_permissions(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            let _ = fs::set_permissions(path, perms);
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
    }

    /// Set directory permissions to 0700 (owner-only access).
    fn set_directory_permissions(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            let _ = fs::set_permissions(path, perms);
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
    }

    /// Rotation par renommage simple : events.jsonl → events.jsonl.1, etc.
    fn rotate_if_needed(&self) {
        let size = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);

        if size < self.max_size_bytes {
            return;
        }

        // Décaler les fichiers existants : .N → .N+1 (du plus ancien au plus récent)
        for i in (1..self.keep_files).rev() {
            let from = format!("{}.{}", self.path.display(), i);
            let to = format!("{}.{}", self.path.display(), i + 1);
            let _ = fs::rename(&from, &to);
        }

        // Le fichier courant devient .1
        let rotated = format!("{}.1", self.path.display());
        let _ = fs::rename(&self.path, &rotated);
    }
}
