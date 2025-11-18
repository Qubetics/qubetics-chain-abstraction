use std::{
    env,
    error::Error,
    path::{Path, PathBuf},
};

/// Database configuration for RocksDB backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseConfig {
    pub path: String,
    pub create_if_missing: bool,
    pub max_open_files: i32,
}

/// Errors returned when configuration is invalid.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    EmptyPath,
    MaxOpenFilesOutOfRange { provided: i32 },
    ParseEnv { var: String, reason: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::EmptyPath => write!(f, "database path must not be empty"),
            ConfigError::MaxOpenFilesOutOfRange { provided } => {
                write!(
                    f,
                    "max_open_files must be a positive integer (got {provided})"
                )
            }
            ConfigError::ParseEnv { var, reason } => {
                write!(f, "failed to parse env var {var}: {reason}")
            }
        }
    }
}

impl Error for ConfigError {}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "./data/rocksdb".to_string(),
            create_if_missing: true,
            max_open_files: 1000,
        }
    }
}

impl DatabaseConfig {
    /// Load configuration from environment variables, falling back to defaults when unset.
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        if let Ok(path) = env::var("DATABASE_PATH") {
            config.path = path;
        }

        if let Ok(create_if_missing) = env::var("DATABASE_CREATE_IF_MISSING") {
            config.create_if_missing =
                create_if_missing
                    .parse::<bool>()
                    .map_err(|e| ConfigError::ParseEnv {
                        var: "DATABASE_CREATE_IF_MISSING".to_string(),
                        reason: e.to_string(),
                    })?;
        }

        if let Ok(max_open_files) = env::var("DATABASE_MAX_OPEN_FILES") {
            config.max_open_files =
                max_open_files
                    .parse::<i32>()
                    .map_err(|e| ConfigError::ParseEnv {
                        var: "DATABASE_MAX_OPEN_FILES".to_string(),
                        reason: e.to_string(),
                    })?;
        }

        config.validate()
    }

    /// Validate the configuration and normalize paths.
    pub fn validate(self) -> Result<Self, ConfigError> {
        if self.path.trim().is_empty() {
            return Err(ConfigError::EmptyPath);
        }

        if self.max_open_files <= 0 {
            return Err(ConfigError::MaxOpenFilesOutOfRange {
                provided: self.max_open_files,
            });
        }

        let path = PathBuf::from(&self.path);
        let normalized_path = path
            .canonicalize()
            .unwrap_or_else(|_| Path::new(&path).to_path_buf());

        Ok(Self {
            path: normalized_path
                .to_str()
                .map(ToString::to_string)
                .unwrap_or_else(|| path.to_string_lossy().to_string()),
            create_if_missing: self.create_if_missing,
            max_open_files: self.max_open_files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    #[test]
    fn default_config_is_valid() {
        let config = DatabaseConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn empty_path_is_rejected() {
        let config = DatabaseConfig {
            path: " ".into(),
            ..Default::default()
        };

        let err = config.validate().expect_err("expected validation to fail");
        assert!(matches!(err, ConfigError::EmptyPath));
    }

    #[test]
    fn non_positive_max_files_is_rejected() {
        let config = DatabaseConfig {
            max_open_files: 0,
            ..Default::default()
        };

        let err = config.validate().expect_err("expected validation to fail");
        assert!(matches!(
            err,
            ConfigError::MaxOpenFilesOutOfRange { provided: 0 }
        ));
    }

    #[test]
    fn env_overrides_are_applied_and_validated() {
        let tmp_dir = tempfile::tempdir().unwrap();
        env::set_var("DATABASE_PATH", tmp_dir.path());
        env::set_var("DATABASE_CREATE_IF_MISSING", "false");
        env::set_var("DATABASE_MAX_OPEN_FILES", "1024");

        let config = DatabaseConfig::from_env().expect("env config should be valid");

        assert_eq!(config.create_if_missing, false);
        assert_eq!(config.max_open_files, 1024);
        assert!(config.path.contains(tmp_dir.path().to_str().unwrap()));
    }

    #[test]
    fn invalid_env_values_propagate_errors() {
        env::set_var("DATABASE_MAX_OPEN_FILES", "not-a-number");
        let err = DatabaseConfig::from_env().expect_err("expected parse error");

        if let ConfigError::ParseEnv { var, .. } = err {
            assert_eq!(var, "DATABASE_MAX_OPEN_FILES");
        } else {
            panic!("unexpected error type");
        }
    }
}
