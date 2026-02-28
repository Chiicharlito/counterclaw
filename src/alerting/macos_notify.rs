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
    pub fn send(&self, event: &SecurityEvent) {
        if !self.enabled {
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
