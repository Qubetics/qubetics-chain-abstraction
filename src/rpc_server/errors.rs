use crate::user_intent_manager::checksum_from_any;

use super::types::ErrorResponse;

#[derive(Debug)]
pub enum RpcError {
    // Input validation errors
    InvalidAddress(String),
    MissingFields(String),
    InvalidRequest(String),

    // Database/storage errors
    DatabaseError(String),
    UserNotFound(String),
    RegistrationFailed(String),

    // Network/system errors
    NetworkError(String),
    DkgNotReady(String),
    Timeout(String),

    // General errors
    InternalError(String),
    SerializationError(String),
}

impl RpcError {
    pub fn to_error_response(&self) -> ErrorResponse {
        match self {
            RpcError::InvalidAddress(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "INVALID_ADDRESS".to_string(),
                message: "Invalid Ethereum address format".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::MissingFields(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "MISSING_FIELDS".to_string(),
                message: "Required fields are missing".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::InvalidRequest(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "INVALID_REQUEST".to_string(),
                message: "Invalid request format".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::DatabaseError(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "DATABASE_ERROR".to_string(),
                message: "Database operation failed".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::UserNotFound(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "USER_NOT_FOUND".to_string(),
                message: "User not found".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::RegistrationFailed(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "REGISTRATION_FAILED".to_string(),
                message: "User registration failed".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::NetworkError(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "NETWORK_ERROR".to_string(),
                message: "Network operation failed".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::DkgNotReady(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "DKG_NOT_READY".to_string(),
                message: "DKG is not ready".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::Timeout(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "TIMEOUT".to_string(),
                message: "Operation timed out".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::InternalError(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "INTERNAL_ERROR".to_string(),
                message: "Internal server error".to_string(),
                details: Some(msg.clone()),
            },
            RpcError::SerializationError(msg) => ErrorResponse {
                status: "error".to_string(),
                error_code: "SERIALIZATION_ERROR".to_string(),
                message: "Data serialization failed".to_string(),
                details: Some(msg.clone()),
            },
        }
    }
}

impl warp::reject::Reject for RpcError {}

pub(crate) fn validate_ethereum_address(address: &str) -> Result<String, RpcError> {
    if address.trim().is_empty() {
        return Err(RpcError::InvalidAddress(
            "Address cannot be empty".to_string(),
        ));
    }

    if !address.starts_with("0x") || address.len() != 42 {
        return Err(RpcError::InvalidAddress(
            "Address must be 42 characters and start with 0x".to_string(),
        ));
    }

    match checksum_from_any(address) {
        Ok(normalized) => Ok(normalized),
        Err(e) => Err(RpcError::InvalidAddress(format!(
            "Invalid address format: {}",
            e
        ))),
    }
}

#[derive(Debug)]
pub enum TransactionError {
    SerializationError,
    NetworkError,
    InvalidRequest,
    PricingUnavailable,
    Overflow,
}

impl warp::reject::Reject for TransactionError {}
