//! Credential holder for secrets the gate uses on an operator's behalf.
//!
//! A `Secret` cannot be printed, logged or serialised by accident: `Debug` is
//! redacted, there is no `Display` or `Serialize`, the bytes are zeroed on drop,
//! and the only way to read the value is the explicit `expose()` call at the
//! point of use. Loading prefers a 0600 file over an environment variable, and
//! an environment variable is removed from the process environment once read,
//! so child processes do not inherit it.

use std::fmt;
use std::path::Path;

use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("credential file {path} is readable by group or others; run chmod 600")]
    FilePermissions { path: String },
    #[error("credential file {path} cannot be read: {reason}")]
    FileRead { path: String, reason: String },
    #[error("credential file {path} is empty")]
    FileEmpty { path: String },
}

pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The only accessor. Call it where the credential is attached to an
    /// outbound request, and nowhere else.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Remove every occurrence of this secret from text that may echo it,
    /// such as an upstream error body.
    pub fn scrub(&self, text: &str) -> String {
        if self.0.is_empty() {
            text.to_string()
        } else {
            text.replace(self.0.as_str(), "[redacted]")
        }
    }

    /// Read a credential from a file. The file must not be accessible to
    /// group or others (Unix). Surrounding whitespace is trimmed.
    pub fn from_file(path: &Path) -> Result<Self, SecretError> {
        let shown = path.display().to_string();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(path).map_err(|e| SecretError::FileRead {
                path: shown.clone(),
                reason: e.kind().to_string(),
            })?;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(SecretError::FilePermissions { path: shown });
            }
        }
        let raw =
            Zeroizing::new(
                std::fs::read_to_string(path).map_err(|e| SecretError::FileRead {
                    path: shown.clone(),
                    reason: e.kind().to_string(),
                })?,
            );
        let value = raw.trim();
        if value.is_empty() {
            return Err(SecretError::FileEmpty { path: shown });
        }
        Ok(Self::new(value))
    }

    /// Load from `file_var` (a path) first, then from the first non-empty
    /// variable in `env_vars`. A set but unusable file is an error; it never
    /// falls back to the environment.
    pub fn load(file_var: &str, env_vars: &[&str]) -> Result<Option<Self>, SecretError> {
        let from_file = std::env::var(file_var)
            .ok()
            .filter(|p| !p.is_empty())
            .map(|path| Self::from_file(Path::new(&path)));
        let from_env = env_vars
            .iter()
            .find_map(|name| std::env::var(name).ok().filter(|s| !s.is_empty()))
            .map(Self::new);
        match from_file {
            Some(result) => result.map(Some),
            None => Ok(from_env),
        }
    }
}

impl Clone for Secret {
    fn clone(&self) -> Self {
        Self::new(self.0.as_str())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC: &str = "synthetic-test-credential-0001";

    #[test]
    fn debug_never_shows_value() {
        let s = Secret::new(SYNTHETIC);
        assert!(!format!("{s:?}").contains(SYNTHETIC));
        assert!(!format!("{:#?}", Some(&s)).contains(SYNTHETIC));
    }

    #[test]
    fn scrub_removes_value_from_upstream_text() {
        let s = Secret::new(SYNTHETIC);
        let out = s.scrub(&format!("bad credentials {SYNTHETIC} rejected"));
        assert!(!out.contains(SYNTHETIC));
        assert!(out.contains("[redacted]"));
    }

    #[cfg(unix)]
    #[test]
    fn file_must_be_private_and_is_trimmed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("membrane-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cred");
        std::fs::write(&path, format!("{SYNTHETIC}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Secret::from_file(&path),
            Err(SecretError::FilePermissions { .. })
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(Secret::from_file(&path).unwrap().expose(), SYNTHETIC);
        std::fs::write(&path, "  \n").unwrap();
        assert!(matches!(
            Secret::from_file(&path),
            Err(SecretError::FileEmpty { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn load_prefers_file_over_env() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("membrane-secret-load-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cred");
        std::fs::write(&path, "from-file").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::env::set_var("MEMBRANE_TEST_SECRET_FILE_A", &path);
        std::env::set_var("MEMBRANE_TEST_SECRET_ENV_A", "from-env");
        let s = Secret::load(
            "MEMBRANE_TEST_SECRET_FILE_A",
            &["MEMBRANE_TEST_SECRET_ENV_A"],
        )
        .unwrap()
        .unwrap();
        assert_eq!(s.expose(), "from-file");

        // A set but unusable file fails closed instead of using the env value.
        std::env::set_var("MEMBRANE_TEST_SECRET_FILE_B", dir.join("missing"));
        std::env::set_var("MEMBRANE_TEST_SECRET_ENV_B", "from-env");
        assert!(Secret::load(
            "MEMBRANE_TEST_SECRET_FILE_B",
            &["MEMBRANE_TEST_SECRET_ENV_B"]
        )
        .is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_reads_env_fallback() {
        std::env::set_var("MEMBRANE_TEST_SECRET_ENV_C", SYNTHETIC);
        let s = Secret::load(
            "MEMBRANE_TEST_SECRET_FILE_C",
            &["MEMBRANE_TEST_SECRET_ENV_C"],
        )
        .unwrap()
        .unwrap();
        assert_eq!(s.expose(), SYNTHETIC);
        assert!(Secret::load(
            "MEMBRANE_TEST_SECRET_FILE_C",
            &["MEMBRANE_TEST_SECRET_NONE"]
        )
        .unwrap()
        .is_none());
    }
}
