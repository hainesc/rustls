/// Configuration for the REALITY anti-probing protocol extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityConfig {
    /// Server's static public key (X25519, 32 bytes).
    pub public_key: [u8; 32],

    /// Short ID for client identification (8 bytes).
    pub short_id: [u8; 8],

    /// Protocol version indicator in Session ID header (default: `[1, 8, 0, 0]`).
    pub version: [u8; 4],
}

impl RealityConfig {
    /// Create a new `RealityConfig` with the server's static public key and an 8-byte short ID.
    pub fn new(public_key: [u8; 32], short_id: [u8; 8]) -> Self {
        Self {
            public_key,
            short_id,
            version: [1, 8, 0, 0],
        }
    }

    /// Set a custom 4-byte version indicator.
    pub fn with_version(mut self, version: [u8; 4]) -> Self {
        self.version = version;
        self
    }
}

