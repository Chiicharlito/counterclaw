//! Launcher module — génération de plist launchd et commandes launchctl.
//!
//! Sépare la logique pure (génération XML, construction de commandes)
//! des opérations IO (écriture fichier, exécution launchctl).

use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// XML escaping — sécurité
// ---------------------------------------------------------------------------

/// Échappe les caractères spéciaux XML dans une string.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ---------------------------------------------------------------------------
// Pure functions — testables sans IO
// ---------------------------------------------------------------------------

/// Génère le contenu XML d'un plist launchd.
///
/// - `label` : identifiant du service (ex: "io.counterclaw.daemon")
/// - `binary_path` : chemin absolu vers le binaire
/// - `config_path` : chemin optionnel vers le fichier de config
pub fn generate_plist(label: &str, binary_path: &str, config_path: Option<&str>) -> String {
    let label_escaped = escape_xml(label);
    let binary_escaped = escape_xml(binary_path);

    let mut program_args = format!(
        "    <key>ProgramArguments</key>\n    <array>\n        <string>{}</string>\n        <string>start</string>\n",
        binary_escaped
    );

    if let Some(cfg) = config_path {
        let cfg_escaped = escape_xml(cfg);
        program_args.push_str(&format!(
            "        <string>--config</string>\n        <string>{}</string>\n",
            cfg_escaped
        ));
    }

    program_args.push_str("    </array>");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
{}
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/counterclaw-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/counterclaw-stderr.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
        label_escaped, program_args
    )
}

/// Retourne le chemin d'installation du plist dans ~/Library/LaunchAgents/.
pub fn plist_install_path(label: &str) -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", label))
}

/// Construit la commande launchctl pour une action donnée.
///
/// - `action` : "load" ou "unload"
/// - `plist_path` : chemin vers le fichier plist
pub fn build_launchctl_command(action: &str, plist_path: &Path) -> Vec<String> {
    vec![
        "launchctl".to_string(),
        action.to_string(),
        plist_path.to_string_lossy().to_string(),
    ]
}

// ---------------------------------------------------------------------------
// LaunchdLauncher — thin IO wrapper
// ---------------------------------------------------------------------------

/// Gère l'installation et le contrôle du daemon via launchd.
pub struct LaunchdLauncher {
    label: String,
    binary_path: String,
    config_path: Option<String>,
}

impl LaunchdLauncher {
    /// Crée un nouveau launcher.
    pub fn new(label: &str, binary_path: &str, config_path: Option<&str>) -> Self {
        Self {
            label: label.to_string(),
            binary_path: binary_path.to_string(),
            config_path: config_path.map(|s| s.to_string()),
        }
    }

    /// Installe le plist et charge le service.
    pub fn install_and_load(&self) -> Result<(), String> {
        let plist_path = plist_install_path(&self.label);

        // Créer le répertoire si nécessaire
        if let Some(parent) = plist_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Cannot create directory: {}", e))?;
        }

        // Générer et écrire le plist
        let plist_content =
            generate_plist(&self.label, &self.binary_path, self.config_path.as_deref());
        std::fs::write(&plist_path, plist_content)
            .map_err(|e| format!("Cannot write plist: {}", e))?;

        // Charger via launchctl
        let cmd = build_launchctl_command("load", &plist_path);
        let output = std::process::Command::new(&cmd[0])
            .args(&cmd[1..])
            .output()
            .map_err(|e| format!("Cannot run launchctl: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("launchctl load failed: {}", stderr));
        }

        Ok(())
    }

    /// Décharge le service.
    pub fn unload(&self) -> Result<(), String> {
        let plist_path = plist_install_path(&self.label);

        if !plist_path.exists() {
            return Err("Plist file not found — daemon is not installed".to_string());
        }

        let cmd = build_launchctl_command("unload", &plist_path);
        let output = std::process::Command::new(&cmd[0])
            .args(&cmd[1..])
            .output()
            .map_err(|e| format!("Cannot run launchctl: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("launchctl unload failed: {}", stderr));
        }

        Ok(())
    }
}
