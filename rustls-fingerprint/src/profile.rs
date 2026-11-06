//! Fingerprint profiles for specific client targets (Chrome, Firefox, Safari, etc.).

use crate::grease::{self, GREASE_PLACEHOLDER};

/// Known TLS extension type constants.
pub mod ext_type {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const STATUS_REQUEST: u16 = 0x0005;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const SCT: u16 = 0x0012;
    pub const PADDING: u16 = 0x0015;
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    pub const COMPRESS_CERTIFICATE: u16 = 0x001b;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const PRE_SHARED_KEY: u16 = 0x0029;
    pub const EARLY_DATA: u16 = 0x002a;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const COOKIE: u16 = 0x002c;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
    pub const CERTIFICATE_AUTHORITIES: u16 = 0x002f;
    pub const POST_HANDSHAKE_AUTH: u16 = 0x0031;
    pub const SIGNATURE_ALGORITHMS_CERT: u16 = 0x0032;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const APPLICATION_SETTINGS: u16 = 0x4469; // ALPS
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

/// Known TLS cipher suite constants (IANA).
pub mod cipher_suite {
    // TLS 1.3
    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

    // TLS 1.2 ECDHE
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: u16 = 0xc013;
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: u16 = 0xc014;

    // TLS 1.2 RSA
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
}

/// Known NamedGroup (Curve) constants.
pub mod named_group {
    pub const SECP256R1: u16 = 0x0017;
    pub const SECP384R1: u16 = 0x0018;
    pub const X25519: u16 = 0x001d;
    pub const X25519_MLKEM768: u16 = 0x11ec; // Chrome post-quantum hybrid group
}

/// A structured profile representing a client fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintProfile {
    /// Preferred order of extension types (including GREASE placeholder).
    pub extension_order: &'static [u16],

    /// Preferred cipher suites in order (including GREASE placeholder).
    pub cipher_suites: &'static [u16],

    /// Preferred supported groups (curves) in order.
    pub supported_groups: &'static [u16],

    /// Preferred signature algorithms.
    pub signature_algorithms: &'static [u16],

    /// Default ALPN protocols (e.g. `["h2", "http/1.1"]`).
    pub default_alpn: &'static [&'static [u8]],

    /// Whether this fingerprint requires GREASE values to be injected.
    pub use_grease: bool,
}

// ---------------------------------------------------------------------------
// Chrome Profiles
// ---------------------------------------------------------------------------

/// Chrome standard extension order (as observed in Chrome 100~130+).
pub static CHROME_EXTENSION_ORDER: &[u16] = &[
    GREASE_PLACEHOLDER,
    ext_type::SERVER_NAME,
    ext_type::EXTENDED_MASTER_SECRET,
    ext_type::RENEGOTIATION_INFO,
    ext_type::SUPPORTED_GROUPS,
    ext_type::EC_POINT_FORMATS,
    ext_type::SESSION_TICKET,
    ext_type::ALPN,
    ext_type::STATUS_REQUEST,
    ext_type::SIGNATURE_ALGORITHMS,
    ext_type::SCT,
    ext_type::KEY_SHARE,
    ext_type::PSK_KEY_EXCHANGE_MODES,
    ext_type::SUPPORTED_VERSIONS,
    ext_type::COMPRESS_CERTIFICATE,
    ext_type::APPLICATION_SETTINGS,
    ext_type::PADDING,
];

/// Chrome standard cipher suites.
pub static CHROME_CIPHER_SUITES: &[u16] = &[
    GREASE_PLACEHOLDER,
    cipher_suite::TLS_AES_128_GCM_SHA256,
    cipher_suite::TLS_AES_256_GCM_SHA384,
    cipher_suite::TLS_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256,
    cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384,
    cipher_suite::TLS_RSA_WITH_AES_128_CBC_SHA,
    cipher_suite::TLS_RSA_WITH_AES_256_CBC_SHA,
];

/// Chrome supported groups (X25519 first, with optional post-quantum hybrid).
pub static CHROME_SUPPORTED_GROUPS: &[u16] = &[
    GREASE_PLACEHOLDER,
    named_group::X25519_MLKEM768,
    named_group::X25519,
    named_group::SECP256R1,
    named_group::SECP384R1,
];

/// Chrome signature algorithms.
pub static CHROME_SIGNATURE_ALGORITHMS: &[u16] = &[
    0x0403, // ecdsa_secp256r1_sha256
    0x0804, // rsa_pss_rsae_sha256
    0x0401, // rsa_pkcs1_sha256
    0x0503, // ecdsa_secp384r1_sha384
    0x0805, // rsa_pss_rsae_sha384
    0x0501, // rsa_pkcs1_sha384
    0x0806, // rsa_pss_rsae_sha512
    0x0601, // rsa_pkcs1_sha512
];

/// Standard ALPN for Chrome.
pub static CHROME_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// The Chrome ClientHello profile.
pub static CHROME_PROFILE: FingerprintProfile = FingerprintProfile {
    extension_order: CHROME_EXTENSION_ORDER,
    cipher_suites: CHROME_CIPHER_SUITES,
    supported_groups: CHROME_SUPPORTED_GROUPS,
    signature_algorithms: CHROME_SIGNATURE_ALGORITHMS,
    default_alpn: CHROME_ALPN,
    use_grease: true,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

impl FingerprintProfile {
    /// Sorts a slice of items according to this profile's `extension_order`.
    ///
    /// Items whose extension type matches a GREASE value or appears in `extension_order`
    /// will be sorted accordingly. Any unknown extensions are pushed to the end.
    pub fn sort_extensions<T, F>(&self, items: &mut [T], mut get_type: F)
    where
        F: FnMut(&T) -> u16,
    {
        items.sort_by_key(|item| {
            let typ = get_type(item);
            let is_item_grease = grease::is_grease(typ);

            for (idx, &expected) in self.extension_order.iter().enumerate() {
                if is_item_grease && expected == GREASE_PLACEHOLDER {
                    return idx;
                }
                if typ == expected {
                    return idx;
                }
            }
            // Unknown extensions go to the end
            usize::MAX
        });
    }
}

