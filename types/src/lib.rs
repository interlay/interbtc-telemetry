use serde::{Deserialize, Serialize};
use sp_core::{
    sr25519::{Pair, Public, Signature},
    Pair as _,
};

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

impl Message {
    pub fn from_payload_and_signer(payload: Payload, signer: &Pair) -> Self {
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = signer.sign(&payload_bytes);
        Self {
            public: signer.public(),
            payload,
            signature,
        }
    }
}

/// Message payload
#[derive(Debug, Serialize, Deserialize)]
pub enum Payload {
    UpdateClient(ClientInfo),
}

/// Information related to the Vault or Relayer
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientInfo {
    /// Client name
    pub name: String,
    /// Client version
    pub version: String,
}
