//! RFC 8701: Generate Random Extensions And Sustain Extensibility (GREASE).

/// The 16 reserved 16-bit GREASE values defined in RFC 8701.
///
/// These values are of the form `0x?a?a` where `?` is one of `0..=f`.
pub const GREASE_TABLE: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// A sentinel value used in templates to indicate that a GREASE value should be substituted.
pub const GREASE_PLACEHOLDER: u16 = 0x0a0a;

/// Checks if a 16-bit integer is a valid RFC 8701 GREASE value.
#[inline]
pub const fn is_grease(val: u16) -> bool {
    (val & 0x0f0f) == 0x0a0a && ((val >> 8) == (val & 0xff))
}

/// Select a GREASE value deterministically from a 16-bit seed.
#[inline]
pub fn select_grease(seed: u16) -> u16 {
    let index = (seed as usize) % GREASE_TABLE.len();
    GREASE_TABLE[index]
}

/// A set of GREASE values chosen for a single connection handshake.
///
/// RFC 8701 recommends selecting different GREASE values across different contexts
/// (cipher suites, supported groups, extensions, etc.) or using a consistent single choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GreaseContext {
    pub cipher_suite: u16,
    pub extension: u16,
    pub supported_group: u16,
    pub alpn: u16,
}

impl GreaseContext {
    /// Generate a context with varied GREASE values derived from a seed.
    pub fn new(seed: u16) -> Self {
        Self {
            cipher_suite: select_grease(seed),
            extension: select_grease(seed.wrapping_add(3)),
            supported_group: select_grease(seed.wrapping_add(7)),
            alpn: select_grease(seed.wrapping_add(11)),
        }
    }
}

