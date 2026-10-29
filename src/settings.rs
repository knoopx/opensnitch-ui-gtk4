
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_ADDRESS: &str = "unix:///tmp/osui.sock";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub default_action: usize,
    pub default_duration: usize,
    pub default_target: usize,
    pub timeout: u32,
    pub popup_position: u32,
    pub advanced: bool,
    pub advanced_dstip: bool,
    pub advanced_dstport: bool,
    pub advanced_uid: bool,
    pub advanced_checksum: bool,
    pub server_address: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_action: 0,
            default_duration: 6,
            default_target: 0,
            timeout: 30,
            popup_position: 0,
            advanced: false,
            advanced_dstip: false,
            advanced_dstport: false,
            advanced_uid: false,
            advanced_checksum: false,
            server_address: None,
        }
    }
}

impl Settings {
    pub fn default_path() -> PathBuf {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("opensnitch").join("settings.conf")
    }

    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(err) => {
                tracing::debug!("settings {}: {err}, using defaults", path.display());
                Self::default()
            }
        }
    }

    pub fn parse(text: &str) -> Self {
        let values = parse_ini(text);
        let def = Self::default();
        let get = |key: &str| values.get(&format!("global/{key}")).map(String::as_str);
        let num = |key: &str, d: usize| get(key).and_then(|v| v.parse().ok()).unwrap_or(d);
        let flag = |key: &str, d: bool| get(key).map_or(d, |v| v == "true");

        Self {
            default_action: num("default_action", def.default_action).min(2),
            default_duration: num("default_duration", def.default_duration).min(8),
            default_target: num("default_target", def.default_target).min(5),
            timeout: u32::try_from(num("default_timeout", def.timeout as usize))
                .unwrap_or(def.timeout),
            popup_position: u32::try_from(num("default_popup_position", 0))
                .unwrap_or(0)
                .min(4),
            advanced: flag("default_popup_advanced", false),
            advanced_dstip: flag("default_popup_advanced_dstip", false),
            advanced_dstport: flag("default_popup_advanced_dstport", false),
            advanced_uid: flag("default_popup_advanced_uid", false),
            advanced_checksum: flag("default_popup_advanced_checksum", false),
            server_address: get("server_address")
                .filter(|v| !v.is_empty())
                .map(String::from),
        }
    }

    pub fn popups_disabled(&self) -> bool {
        self.timeout == 0
    }
}

fn parse_ini(text: &str) -> HashMap<String, String> {
    let mut section = String::new();
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
        } else if let Some((key, value)) = line.split_once('=')
            && !line.starts_with(';')
            && !line.starts_with('#')
        {
            out.insert(
                format!("{section}/{}", key.trim()),
                value.trim().to_string(),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "[global]\ndefault_action=2\ndefault_duration=8\ndefault_target=0\n\
        default_timeout=30\ndefault_popup_position=1\ndefault_popup_advanced=true\n\
        server_address=unix:///tmp/osui.sock\n\n[promptDialog]\ngeometry=@ByteArray(\\x1)\n";

    #[test]
    fn parses_global_keys() {
        let s = Settings::parse(SAMPLE);
        assert_eq!(s.default_action, 2);
        assert_eq!(s.default_duration, 8);
        assert_eq!(s.timeout, 30);
        assert_eq!(s.popup_position, 1);
        assert!(s.advanced);
        assert!(!s.advanced_uid);
        assert_eq!(s.server_address.as_deref(), Some("unix:///tmp/osui.sock"));
    }

    #[test]
    fn missing_keys_use_defaults() {
        assert_eq!(Settings::parse(""), Settings::default());
    }

    #[test]
    fn ignores_other_sections_and_clamps() {
        let s = Settings::parse("[other]\ndefault_action=1\n[global]\ndefault_duration=99\n");
        assert_eq!(s.default_action, 0);
        assert_eq!(s.default_duration, 8);
    }

    #[test]
    fn zero_timeout_disables_popups() {
        assert!(Settings::parse("[global]\ndefault_timeout=0\n").popups_disabled());
    }
}
