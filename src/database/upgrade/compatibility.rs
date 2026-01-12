/// Version compatibility management for rolling upgrades
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionRange {
    pub min: String,
    pub max: String,
}

impl VersionRange {
    pub fn new(min: &str, max: &str) -> Self {
        Self {
            min: min.to_string(),
            max: max.to_string(),
        }
    }

    pub fn contains(&self, version: &str) -> Result<bool> {
        use std::cmp::Ordering;
        Ok(compare_versions(version, &self.min)? >= Ordering::Equal
            && compare_versions(version, &self.max)? <= Ordering::Equal)
    }
}

/// Compatibility matrix for version coexistence
#[derive(Clone)]
pub struct CompatibilityMatrix {
    compatibility_rules: HashMap<String, VersionRange>,
}

impl CompatibilityMatrix {
    pub fn new() -> Self {
        let mut rules = HashMap::new();

        // Define compatibility ranges
        // v0.1.x can work with v0.1.x only
        rules.insert("0.1.0".to_string(), VersionRange::new("0.1.0", "0.1.99"));

        // v0.2.x can work with v0.1.x and v0.2.x (rolling upgrade support)
        rules.insert("0.2.0".to_string(), VersionRange::new("0.1.0", "0.2.99"));

        // Add more version ranges as needed

        Self {
            compatibility_rules: rules,
        }
    }

    /// Check if two versions can operate together
    pub fn are_compatible(&self, v1: &str, v2: &str) -> Result<bool> {
        // Same version is always compatible
        if v1 == v2 {
            return Ok(true);
        }

        // Check if v1's range includes v2
        if let Some(range) = self.compatibility_rules.get(v1) {
            if range.contains(v2)? {
                return Ok(true);
            }
        }

        // Check if v2's range includes v1
        if let Some(range) = self.compatibility_rules.get(v2) {
            if range.contains(v1)? {
                return Ok(true);
            }
        }

        // Check major version compatibility (conservative approach)
        let (v1_major, _, _) = parse_version(v1)?;
        let (v2_major, _, _) = parse_version(v2)?;

        // Different major versions are incompatible
        Ok(v1_major == v2_major)
    }

    /// Get minimum required version for network
    pub fn get_minimum_network_version(&self, peer_versions: &[String]) -> Option<String> {
        peer_versions
            .iter()
            .min_by(|a, b| compare_versions(a, b).unwrap_or(std::cmp::Ordering::Equal))
            .cloned()
    }

    /// Get maximum version in network
    pub fn get_maximum_network_version(&self, peer_versions: &[String]) -> Option<String> {
        peer_versions
            .iter()
            .max_by(|a, b| compare_versions(a, b).unwrap_or(std::cmp::Ordering::Equal))
            .cloned()
    }

    /// Check if new node can join network
    pub fn can_join_network(&self, my_version: &str, network_versions: &[String]) -> Result<bool> {
        if network_versions.is_empty() {
            return Ok(true); // First node can always join
        }

        // Check compatibility with all existing nodes
        for version in network_versions {
            if !self.are_compatible(my_version, version)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get version distribution
    pub fn get_version_distribution(&self, peer_versions: &[String]) -> HashMap<String, usize> {
        let mut distribution = HashMap::new();

        for version in peer_versions {
            *distribution.entry(version.clone()).or_insert(0) += 1;
        }

        distribution
    }

    /// Check if network is ready for feature that requires minimum version
    pub fn is_feature_available(
        &self,
        peer_versions: &[String],
        required_version: &str,
        required_ratio: f64,
    ) -> Result<bool> {
        if peer_versions.is_empty() {
            return Ok(false);
        }

        let compatible_count = peer_versions
            .iter()
            .filter(|v| {
                compare_versions(v, required_version).unwrap_or(std::cmp::Ordering::Less)
                    >= std::cmp::Ordering::Equal
            })
            .count();

        let ratio = compatible_count as f64 / peer_versions.len() as f64;
        Ok(ratio >= required_ratio)
    }
}

impl Default for CompatibilityMatrix {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse semantic version string
pub fn parse_version(version: &str) -> Result<(u32, u32, u32)> {
    let parts: Vec<&str> = version.split('.').collect();

    if parts.len() != 3 {
        return Err(anyhow!("Invalid semantic version format: {}", version));
    }

    Ok((
        parts[0]
            .parse()
            .map_err(|e| anyhow!("Invalid major version: {}", e))?,
        parts[1]
            .parse()
            .map_err(|e| anyhow!("Invalid minor version: {}", e))?,
        parts[2]
            .parse()
            .map_err(|e| anyhow!("Invalid patch version: {}", e))?,
    ))
}

/// Compare two semantic versions
/// Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2
pub fn compare_versions(v1: &str, v2: &str) -> Result<std::cmp::Ordering> {
    let (v1_major, v1_minor, v1_patch) = parse_version(v1)?;
    let (v2_major, v2_minor, v2_patch) = parse_version(v2)?;

    match v1_major.cmp(&v2_major) {
        std::cmp::Ordering::Equal => match v1_minor.cmp(&v2_minor) {
            std::cmp::Ordering::Equal => Ok(v1_patch.cmp(&v2_patch)),
            other => Ok(other),
        },
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.2.3").unwrap(), (1, 2, 3));
        assert_eq!(parse_version("0.1.0").unwrap(), (0, 1, 0));
        assert!(parse_version("invalid").is_err());
    }

    #[test]
    fn test_compare_versions() {
        assert_eq!(
            compare_versions("1.0.0", "1.0.0").unwrap(),
            std::cmp::Ordering::Equal
        );
        assert_eq!(
            compare_versions("1.0.0", "2.0.0").unwrap(),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            compare_versions("2.0.0", "1.0.0").unwrap(),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_versions("1.2.3", "1.2.4").unwrap(),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_compatibility() {
        let matrix = CompatibilityMatrix::new();

        // Same version is compatible
        assert!(matrix.are_compatible("0.1.0", "0.1.0").unwrap());

        // 0.2.0 is compatible with 0.1.0 (backward compatible)
        assert!(matrix.are_compatible("0.2.0", "0.1.0").unwrap());

        // Different major versions are incompatible
        assert!(!matrix.are_compatible("1.0.0", "2.0.0").unwrap());
    }

    #[test]
    fn test_can_join_network() {
        let matrix = CompatibilityMatrix::new();

        // First node can join empty network
        assert!(matrix.can_join_network("0.1.0", &[]).unwrap());

        // Compatible version can join
        let network = vec!["0.1.0".to_string()];
        assert!(matrix.can_join_network("0.2.0", &network).unwrap());

        // Same version can join
        assert!(matrix.can_join_network("0.1.0", &network).unwrap());
    }

    #[test]
    fn test_version_distribution() {
        let matrix = CompatibilityMatrix::new();
        let versions = vec![
            "0.1.0".to_string(),
            "0.1.0".to_string(),
            "0.2.0".to_string(),
        ];

        let distribution = matrix.get_version_distribution(&versions);
        assert_eq!(distribution.get("0.1.0"), Some(&2));
        assert_eq!(distribution.get("0.2.0"), Some(&1));
    }
}
