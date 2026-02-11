//! Compact formatting helpers for trace output.

use std::fmt;

/// Wrapper that displays large round numbers compactly.
///
/// Exact multiples of powers of 1000 are shortened:
/// - `1_000` → `1K`
/// - `20_000_000` → `20M`
/// - `3_000_000_000` → `3B`
/// - `1_000_000_000_000` → `1T`
///
/// Non-round numbers pass through unchanged: `12345` → `12345`.
pub struct FmtN(pub u64);

impl fmt::Display for FmtN {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self.0;
        const SUFFIXES: &[(u64, &str)] = &[
            (1_000_000_000_000, "T"),
            (1_000_000_000, "B"),
            (1_000_000, "M"),
            (1_000, "K"),
        ];
        for &(divisor, suffix) in SUFFIXES {
            if v >= divisor && v.is_multiple_of(divisor) {
                return write!(f, "{}{}", v / divisor, suffix);
            }
        }
        write!(f, "{v}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fmt_n() {
        assert_eq!(FmtN(0).to_string(), "0");
        assert_eq!(FmtN(999).to_string(), "999");
        assert_eq!(FmtN(1_000).to_string(), "1K");
        assert_eq!(FmtN(20_000).to_string(), "20K");
        assert_eq!(FmtN(1_500).to_string(), "1500");
        assert_eq!(FmtN(1_000_000).to_string(), "1M");
        assert_eq!(FmtN(20_000_000).to_string(), "20M");
        assert_eq!(FmtN(3_000_000_000).to_string(), "3B");
        assert_eq!(FmtN(1_000_000_000_000).to_string(), "1T");
        assert_eq!(FmtN(12345).to_string(), "12345");
        assert_eq!(FmtN(5_000_000).to_string(), "5M");
        assert_eq!(FmtN(100_000_000).to_string(), "100M");
    }
}
