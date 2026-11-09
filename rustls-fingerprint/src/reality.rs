//! REALITY protocol Session ID computation and verification.

use aws_lc_rs::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::hkdf;

/// Custom single-use nonce sequence for aws-lc-rs keys.
struct OneNonceSequence(Option<Nonce>);

impl NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        self.0.take().ok_or(Unspecified)
    }
}

/// Compute the REALITY 32-byte Session ID for a ClientHello.
///
/// # Protocol Specification:
/// 1. `auth_key = HKDF-SHA256(salt = random[0..20], ikm = ecdh_secret, info = "REALITY", len = 32)`
/// 2. `plaintext = [version (4B), timestamp (4B BE), short_id (8B)]` (16 bytes)
/// 3. `nonce = random[20..32]` (12 bytes)
/// 4. `session_id = ChaCha20Poly1305_Seal(auth_key, nonce, plaintext, aad)` (32 bytes = 16B ciphertext + 16B tag)
pub fn compute_reality_session_id(
    shared_secret: &[u8; 32],
    random: &[u8; 32],
    short_id: &[u8; 8],
    timestamp: u32,
    version: [u8; 4],
    aad: &[u8],
) -> Result<[u8; 32], Unspecified> {
    // 1. Derive auth_key
    let mut auth_key = [0u8; 32];
    hkdf::Salt::new(hkdf::HKDF_SHA256, &random[..20])
        .extract(shared_secret)
        .expand(&[b"REALITY"], hkdf::HKDF_SHA256)?
        .fill(&mut auth_key)?;

    // 2. Build 16-byte plaintext
    let mut plaintext = [0u8; 16];
    plaintext[0..4].copy_from_slice(&version);
    plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..16].copy_from_slice(short_id);

    // 3. Encrypt via AES-256-GCM
    let nonce_bytes: [u8; 12] = random[20..32].try_into().map_err(|_| Unspecified)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    let unbound_key = UnboundKey::new(&AES_256_GCM, &auth_key)?;
    let mut sealing_key = SealingKey::new(unbound_key, OneNonceSequence(Some(nonce)));

    sealing_key.seal_in_place_append_tag(Aad::from(aad), &mut in_out)?;

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&in_out[..32]);
    Ok(session_id)
}

/// Decrypt and verify a REALITY Session ID on the server side.
///
/// Returns the decrypted 16-byte plaintext `[version (4B), timestamp (4B BE), short_id (8B)]`.
pub fn verify_reality_session_id(
    shared_secret: &[u8; 32],
    random: &[u8; 32],
    session_id: &[u8; 32],
    aad: &[u8],
) -> Result<[u8; 16], Unspecified> {
    let mut auth_key = [0u8; 32];
    hkdf::Salt::new(hkdf::HKDF_SHA256, &random[..20])
        .extract(shared_secret)
        .expand(&[b"REALITY"], hkdf::HKDF_SHA256)?
        .fill(&mut auth_key)?;

    let nonce_bytes: [u8; 12] = random[20..32].try_into().map_err(|_| Unspecified)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = session_id.to_vec();
    let unbound_key = UnboundKey::new(&AES_256_GCM, &auth_key)?;
    let mut opening_key = OpeningKey::new(unbound_key, OneNonceSequence(Some(nonce)));

    let decrypted = opening_key.open_in_place(Aad::from(aad), &mut in_out)?;

    let mut plaintext = [0u8; 16];
    plaintext.copy_from_slice(decrypted);
    Ok(plaintext)
}

/// Compute X25519 shared secret between server static private key and client ephemeral public key.
pub fn compute_x25519_shared_secret(
    server_private_key: &[u8; 32],
    client_public_key: &[u8; 32],
) -> Result<[u8; 32], Unspecified> {
    let priv_key =
        aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_rs::agreement::X25519, server_private_key)
            .map_err(|_| Unspecified)?;
    let peer_key =
        aws_lc_rs::agreement::UnparsedPublicKey::new(&aws_lc_rs::agreement::X25519, client_public_key);
    aws_lc_rs::agreement::agree(&priv_key, peer_key, Unspecified, |secret| {
        let mut s = [0u8; 32];
        if secret.len() == 32 {
            s.copy_from_slice(secret);
            Ok(s)
        } else {
            Err(Unspecified)
        }
    })
}

/// Parsed fields from a ClientHello message needed for REALITY verification.
#[derive(Debug, Clone)]
pub struct ParsedClientHello<'a> {
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub server_name: Option<&'a str>,
    pub client_public_key: Option<[u8; 32]>,
}

/// Parse a raw TLS ClientHello record (starting with 0x16 0x03 0x01/03).
pub fn parse_client_hello<'a>(data: &'a [u8]) -> Option<ParsedClientHello<'a>> {
    if data.len() < 5 + 4 + 2 + 32 + 1 {
        return None;
    }
    if data[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let mut pos = 5;
    if data[pos] != 0x01 {
        return None;
    }
    pos += 1;
    pos += 3; // handshake length
    pos += 2; // client version

    let mut random = [0u8; 32];
    random.copy_from_slice(&data[pos..pos + 32]);
    pos += 32;

    let session_id_len = data[pos] as usize;
    pos += 1;
    if pos + session_id_len > data.len() {
        return None;
    }
    let mut session_id = [0u8; 32];
    if session_id_len == 32 {
        session_id.copy_from_slice(&data[pos..pos + 32]);
    }
    pos += session_id_len;

    if pos + 2 > data.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos + 1 > data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    if pos + 2 > data.len() {
        return Some(ParsedClientHello {
            random,
            session_id,
            server_name: None,
            client_public_key: None,
        });
    }
    let exts_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let exts_end = pos + exts_len;
    if exts_end > data.len() {
        return None;
    }

    let mut server_name = None;
    let mut client_public_key = None;

    while pos + 4 <= exts_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > exts_end {
            break;
        }
        let ext_data = &data[pos..pos + ext_len];
        pos += ext_len;

        match ext_type {
            // server_name (SNI)
            0x0000 => {
                if ext_data.len() >= 5 {
                    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
                    if ext_data.len() >= 5 + name_len {
                        server_name = core::str::from_utf8(&ext_data[5..5 + name_len]).ok();
                    }
                }
            }
            // key_share (0x0033)
            0x0033 => {
                if ext_data.len() >= 2 {
                    let shares_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    let mut s_pos = 2;
                    let s_end = 2 + shares_len;
                    while s_pos + 4 <= s_end && s_pos + 4 <= ext_data.len() {
                        let group = u16::from_be_bytes([ext_data[s_pos], ext_data[s_pos + 1]]);
                        let key_len =
                            u16::from_be_bytes([ext_data[s_pos + 2], ext_data[s_pos + 3]]) as usize;
                        s_pos += 4;
                        if s_pos + key_len > ext_data.len() {
                            break;
                        }
                        if group == 0x001d && key_len == 32 {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&ext_data[s_pos..s_pos + 32]);
                            client_public_key = Some(key);
                            break;
                        } else if group == 0x11ec && key_len == 1184 + 32 {
                            // X25519MLKEM768 hybrid: trailing 32 bytes is X25519 public key
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&ext_data[s_pos + 1184..s_pos + 1216]);
                            client_public_key = Some(key);
                        }
                        s_pos += key_len;
                    }
                }
            }
            _ => {}
        }
    }

    Some(ParsedClientHello {
        random,
        session_id,
        server_name,
        client_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_roundtrip() {
        let shared_secret = [0x42u8; 32];
        let random = [0x77u8; 32];
        let short_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let timestamp = 1714000000;
        let version = [1, 8, 0, 0];
        let aad = b"test_client_hello_raw";

        let session_id = compute_reality_session_id(
            &shared_secret,
            &random,
            &short_id,
            timestamp,
            version,
            aad,
        )
        .unwrap();

        assert_ne!(session_id, [0u8; 32]);

        let decrypted =
            verify_reality_session_id(&shared_secret, &random, &session_id, aad).unwrap();

        assert_eq!(&decrypted[0..4], &version);
        assert_eq!(&decrypted[4..8], &timestamp.to_be_bytes());
        assert_eq!(&decrypted[8..16], &short_id);
    }

    #[test]
    fn test_x25519_agreement() {
        let priv_a = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f,
        ];
        // Calculate pub_a via aws-lc-rs
        let priv_key_a =
            aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_rs::agreement::X25519, &priv_a)
                .unwrap();
        let pub_a = priv_key_a.compute_public_key().unwrap();

        let priv_b = [
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
            0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
            0x6c, 0x6d, 0x6e, 0x6f,
        ];
        let priv_key_b =
            aws_lc_rs::agreement::PrivateKey::from_private_key(&aws_lc_rs::agreement::X25519, &priv_b)
                .unwrap();
        let pub_b = priv_key_b.compute_public_key().unwrap();

        let sec_a = compute_x25519_shared_secret(&priv_a, pub_b.as_ref().try_into().unwrap()).unwrap();
        let sec_b = compute_x25519_shared_secret(&priv_b, pub_a.as_ref().try_into().unwrap()).unwrap();

        assert_eq!(sec_a, sec_b);
    }
}
