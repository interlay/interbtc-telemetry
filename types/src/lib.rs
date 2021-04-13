use serde::{Deserialize, Serialize};
use sp_core::sr25519::{Public, Signature};

/// Signed message
#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    /// Public key
    pub public: Public,
    /// Message payload
    pub payload: Payload,
    /// Signature of payload bytes
    pub signature: Signature,
}

/// Message payload
#[derive(Debug, Serialize, Deserialize)]
pub enum Payload {
    UpdateClient(ClientInfo),
}

/// Information related to the Vault or Relayer
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Software version
    pub version: String,
}
