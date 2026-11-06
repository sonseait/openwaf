//! Bounded generation of URL/header-safe correlation IDs using OpenSSL's CSPRNG.
use anyhow::{Result, bail};

const ALPHABET: &[u8; 63] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";

pub fn generate() -> Result<String> {
    let mut id = String::with_capacity(openwaf_telemetry::request_id::LENGTH);
    // Rejection sampling avoids modulo bias. Bound RNG work even on repeated
    // rejected bytes; a generation failure fails the request, never reuses an ID.
    for _ in 0..4 {
        let mut random = [0; 64];
        openssl::rand::rand_bytes(&mut random)?;
        for byte in random {
            if byte < 252 {
                id.push(ALPHABET[usize::from(byte) % ALPHABET.len()] as char);
                if id.len() == openwaf_telemetry::request_id::LENGTH {
                    return Ok(id);
                }
            }
        }
    }
    bail!("request ID generation exhausted its sampling budget")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generated_ids_are_valid_unique_and_use_the_full_alphabet() {
        let mut ids = HashSet::new();
        let mut characters = HashSet::new();
        for _ in 0..256 {
            let id = generate().expect("CSPRNG");
            assert_eq!(id.len(), openwaf_telemetry::request_id::LENGTH);
            assert!(openwaf_telemetry::request_id::valid(&id));
            characters.extend(id.bytes());
            assert!(ids.insert(id));
        }
        assert!(ALPHABET.iter().all(|byte| characters.contains(byte)));
    }
}
