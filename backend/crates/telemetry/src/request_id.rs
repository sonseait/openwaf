//! Shared reference format for live lookup and bounded history queries.
pub const LENGTH: usize = 64;
const LEGACY_LENGTH: usize = 32;

pub fn valid(id: &str) -> bool {
    matches!(id.len(), LENGTH | LEGACY_LENGTH)
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_mixed_case_digits_underscores_and_legacy_hex() {
        assert!(valid(&"aB3_dE6_gH9_jK2_mN5_pQ8_sT1_vW4_".repeat(2)));
        assert!(valid("aB3_dE6_gH9_jK2_mN5_pQ8_sT1_vW4_"));
        assert!(valid("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn rejects_unsafe_characters_unicode_and_wrong_lengths() {
        for length in [0, 31, 33, 63, 65, 128] {
            assert!(!valid(&"a".repeat(length)));
        }
        for length in [LEGACY_LENGTH, LENGTH] {
            for suffix in ["'", "\"", "\\", "/", "-", " ", "\n", "é"] {
                assert!(!valid(&format!("{}{}", "a".repeat(length - 1), suffix)));
            }
        }
    }
}
