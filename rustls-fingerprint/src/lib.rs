//! TLS ClientHello Fingerprinting Profiles and Utilities.
//!
//! This crate provides pre-configured ClientHello profiles (such as Google Chrome)
//! and GREASE generation (RFC 8701) to allow `rustls` to mimic mainstream browser
//! TLS fingerprints (JA3/JA4) for anti-censorship and anti-probing applications.

#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_extern_crates)]
extern crate alloc;

pub mod grease;
pub mod profile;
pub mod reality;

pub use grease::{GreaseContext, GREASE_TABLE};
pub use profile::{FingerprintProfile, CHROME_PROFILE};
pub use reality::{
    compute_reality_session_id, compute_x25519_shared_secret, parse_client_hello,
    verify_reality_session_id, ParsedClientHello,
};

/// Predefined or custom ClientHello fingerprint target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ClientFingerprint {
    /// Standard Google Chrome ClientHello profile with RFC 8701 GREASE injection
    /// and Chrome extension ordering.
    #[default]
    Chrome,

    /// Fixed profile pinned to Google Chrome 120+.
    Chrome120,

    /// Randomized extension ordering with GREASE values (good general anti-fingerprint).
    Randomized,

    /// No special fingerprint modifications; use rustls standard behavior.
    None,
}

impl ClientFingerprint {
    /// Returns the associated `FingerprintProfile` if this fingerprint has a static profile.
    pub fn profile(&self) -> Option<&'static FingerprintProfile> {
        match self {
            Self::Chrome | Self::Chrome120 => Some(&CHROME_PROFILE),
            Self::Randomized | Self::None => None,
        }
    }

    /// Whether this fingerprint variant is active.
    pub fn is_active(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Whether this fingerprint enables GREASE generation.
    pub fn uses_grease(&self) -> bool {
        match self {
            Self::Chrome | Self::Chrome120 | Self::Randomized => true,
            Self::None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_detection() {
        for &val in &GREASE_TABLE {
            assert!(grease::is_grease(val));
        }
        assert!(!grease::is_grease(0x0000));
        assert!(!grease::is_grease(0x1301));
    }

    #[test]
    fn test_chrome_profile_order() {
        let profile = ClientFingerprint::Chrome.profile().unwrap();
        assert!(profile.use_grease);

        let mut sample_exts = vec![
            profile::ext_type::SUPPORTED_VERSIONS,
            profile::ext_type::SERVER_NAME,
            0x1a1a, // GREASE extension
            profile::ext_type::KEY_SHARE,
        ];

        profile.sort_extensions(&mut sample_exts, |&t| t);

        assert_eq!(
            sample_exts,
            vec![
                0x1a1a, // GREASE should be first in Chrome profile
                profile::ext_type::SERVER_NAME,
                profile::ext_type::KEY_SHARE,
                profile::ext_type::SUPPORTED_VERSIONS,
            ]
        );
    }
}

