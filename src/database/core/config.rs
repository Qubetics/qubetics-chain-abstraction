/// Database configuration for RocksDB backend.
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub path: String,
    pub create_if_missing: bool,
    pub max_open_files: i32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "./data/rocksdb".to_string(),
            create_if_missing: true,
            max_open_files: 1000,
        }
    }
}
