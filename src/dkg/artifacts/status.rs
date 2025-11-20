use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};

pub type DKGCompletionCallback = Box<dyn Fn(Scalar, ProjectivePoint) + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DKGStatus {
    New,
    Error { kind: String },
    Started,
    Completed,
}
