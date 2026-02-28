//! Notifications macOS natives via osascript.
//!
//! Envoie des notifications système (celles qui apparaissent en haut
//! à droite de l'écran). C'est du fire-and-forget : si ça échoue,
//! on log mais on ne propage pas l'erreur.

use crate::types::SecurityEvent;
use std::process::Command;

/// Notificateur macOS.
pub struct MacosNotifier {
    enabled: bool,
}

impl MacosNotifier {
    /// Crée un nouveau notificateur.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Retourne si les notifications sont activées.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Envoie une notification pour un événement de sécurité.
    ///
    /// Skips notification silently (with log warning) when running as a
    /// LaunchDaemon with no GUI session — osascript cannot display
    /// notifications without a window server connection.
    pub fn send(&self, event: &SecurityEvent) {
        if !self.enabled {
            return;
        }

        if !has_gui_session() {
            eprintln!(
                "[counterclaw] Skipping macOS notification (no GUI session — running as daemon?)"
            );
            return;
        }

        let title = format!("[{}] {}", event.severity, event.module);
        let message = &event.description;

        send_notification(&title, message);
    }
}

/// Envoie une notification macOS via osascript.
/// Les guillemets dans le titre/message sont échappés pour éviter l'injection.
fn send_notification(title: &str, message: &str) {
    let safe_title = sanitize(title);
    let safe_message = sanitize(message);

    let script = format!(
        r#"display notification "{}" with title "CounterClaw" subtitle "{}""#,
        safe_message, safe_title
    );

    let result = Command::new("osascript").args(["-e", &script]).spawn();

    if let Err(e) = result {
        eprintln!("[counterclaw] macOS notification failed: {}", e);
    }
}

/// Detects if the current process has access to a GUI session.
///
/// Returns false when running as a LaunchDaemon (root, no window server).
/// Uses the DISPLAY env var on Linux and checks for window server
/// accessibility on macOS via `/usr/sbin/system_profiler` absence or
/// by checking if the process runs without a console user.
pub fn has_gui_session() -> bool {
    // On macOS, a LaunchDaemon run as root has no console user session.
    // We check if there is a console user via scutil.
    #[cfg(target_os = "macos")]
    {
        // If TERM_PROGRAM or SSH_TTY is set, we're likely in a terminal
        if std::env::var("TERM_PROGRAM").is_ok() || std::env::var("TERM").is_ok() {
            return true;
        }
        // Try to detect console user via `stat -f %u /dev/console`
        // If it returns 0 (root) or fails, there's likely no GUI user logged in
        match Command::new("stat")
            .args(["-f", "%u", "/dev/console"])
            .output()
        {
            Ok(output) => {
                let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
                // UID 0 = root = no user GUI session
                uid != "0" && !uid.is_empty()
            }
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        // On Linux, check for DISPLAY or WAYLAND_DISPLAY
        std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok()
    }
}

/// Sanitize une chaîne pour l'injection osascript.
///
/// Protections appliquées :
/// - Échappe les backslashes (doit être en premier)
/// - Échappe les guillemets doubles (syntaxe AppleScript)
/// - Échappe les backticks (prévient l'interpolation de commandes)
/// - Échappe le dollar sign (prévient `$()` command substitution)
/// - Échappe les accolades (prévient le brace expansion)
/// - Remplace les newlines/CR par des espaces (prévient l'injection multi-lignes)
/// - Tronque à 256 caractères max (prévient les buffer overflows)
pub fn sanitize(input: &str) -> String {
    let mut result = input
        .replace('\\', "\\\\") // Must be first
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
        .replace('{', "\\{")
        .replace('}', "\\}")
        .replace(['\n', '\r'], " ");

    // Truncate to 256 chars max
    if result.len() > 256 {
        result.truncate(256);
    }
    result
}
