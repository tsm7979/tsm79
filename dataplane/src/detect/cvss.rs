/// CVSS 3.1 base score computation and composite risk scoring.
///
/// Reference: https://www.first.org/cvss/v3.1/specification-document
///
/// For TSM's purposes we use the pre-computed base scores stored in
/// PATTERN_META and combine them with detection confidence, count of
/// distinct PII types, and entropy signals into a 0–100 composite score.

/// A raw CVSS 3.1 base score (0.0 – 10.0).
pub type CvssScore = f64;

/// Severity band derived from a CVSS or composite score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::None     => "none",
            Severity::Low      => "low",
            Severity::Medium   => "medium",
            Severity::High     => "high",
            Severity::Critical => "critical",
        }
    }

    /// Derive severity from a CVSS 3.1 base score per spec §5.
    pub fn from_cvss(score: CvssScore) -> Self {
        match score {
            s if s == 0.0        => Severity::None,
            s if s < 4.0         => Severity::Low,
            s if s < 7.0         => Severity::Medium,
            s if s < 9.0         => Severity::High,
            _                    => Severity::Critical,
        }
    }

    /// Derive severity from a composite risk score (0–100 scale).
    pub fn from_risk(score: f64) -> Self {
        match score {
            s if s < 10.0  => Severity::None,
            s if s < 35.0  => Severity::Low,
            s if s < 60.0  => Severity::Medium,
            s if s < 80.0  => Severity::High,
            _              => Severity::Critical,
        }
    }
}

// ── Composite risk score ──────────────────────────────────────────────────────

/// Inputs for composite risk calculation.
pub struct RiskInputs {
    /// CVSS base score of the highest-severity matched pattern (0–10).
    pub max_cvss: CvssScore,
    /// Number of distinct PII/secret types detected.
    pub pii_count: usize,
    /// Whether any token exceeded the high-entropy threshold.
    pub high_entropy: bool,
    /// Entropy risk contribution (0–30), from entropy::EntropyVerdict.
    pub entropy_contribution: f64,
    /// Whether a structural hit (JWT, base64 blob, hex blob) was found.
    pub structural_hit: bool,
    /// Whether a jailbreak pattern was matched.
    pub jailbreak: bool,
}

/// Compute a composite risk score in the range 0.0 – 100.0.
///
/// Weighting:
///   - CVSS base score  → 0–60 points  (cvss / 10.0 * 60)
///   - PII type count   → 0–20 points  (min(count, 5) * 4)
///   - Entropy          → 0–30 points  (entropy_contribution, capped at 20)
///   - Structural hit   → +10 points
///   - Jailbreak        → +15 points
///
/// The result is clamped to [0, 100].
pub fn composite_score(inputs: &RiskInputs) -> f64 {
    let cvss_part        = (inputs.max_cvss / 10.0 * 60.0).clamp(0.0, 60.0);
    let pii_part         = (inputs.pii_count.min(5) as f64) * 4.0;
    let entropy_part     = inputs.entropy_contribution.clamp(0.0, 20.0);
    let structural_part  = if inputs.structural_hit { 10.0 } else { 0.0 };
    let jailbreak_part   = if inputs.jailbreak { 15.0 } else { 0.0 };

    (cvss_part + pii_part + entropy_part + structural_part + jailbreak_part).clamp(0.0, 100.0)
}

/// Map a pattern match count and per-pattern CVSS score to a risk contribution.
/// Multiple matches of the same type (e.g., 3 SSNs) increase risk moderately.
pub fn pattern_risk(cvss: CvssScore, match_count: usize) -> f64 {
    let base = cvss / 10.0 * 60.0;
    // Each additional match adds 5 points, capped at +20
    let extra = ((match_count.saturating_sub(1)) as f64 * 5.0).min(20.0);
    (base + extra).clamp(0.0, 80.0)
}

/// Validate a credit card number string using the Luhn algorithm.
///
/// Strips any non-digit characters before checking. Returns `true` iff
/// the number is 13–19 digits long and passes Luhn validation.
/// Use this to eliminate random-number false positives from the CC pattern.
pub fn luhn_valid(digits: &str) -> bool {
    let nums: Vec<u32> = digits
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u32 - '0' as u32)
        .collect();
    let len = nums.len();
    if len < 13 || len > 19 {
        return false;
    }
    let sum: u32 = nums
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let v = d * 2;
                if v > 9 { v - 9 } else { v }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_to_severity() {
        assert_eq!(Severity::from_cvss(0.0),   Severity::None);
        assert_eq!(Severity::from_cvss(3.9),   Severity::Low);
        assert_eq!(Severity::from_cvss(5.0),   Severity::Medium);
        assert_eq!(Severity::from_cvss(7.5),   Severity::High);
        assert_eq!(Severity::from_cvss(9.5),   Severity::Critical);
        assert_eq!(Severity::from_cvss(10.0),  Severity::Critical);
    }

    #[test]
    fn ssn_only_scores_high() {
        let score = composite_score(&RiskInputs {
            max_cvss:             9.1,
            pii_count:            1,
            high_entropy:         false,
            entropy_contribution: 0.0,
            structural_hit:       false,
            jailbreak:            false,
        });
        // 9.1/10*60 = 54.6 + 4 = 58.6
        assert!((score - 58.6).abs() < 0.5, "score={}", score);
        assert_eq!(Severity::from_risk(score), Severity::Medium);
    }

    #[test]
    fn openai_key_plus_entropy_scores_critical() {
        let score = composite_score(&RiskInputs {
            max_cvss:             9.8,
            pii_count:            1,
            high_entropy:         true,
            entropy_contribution: 25.0,
            structural_hit:       false,
            jailbreak:            false,
        });
        // 58.8 + 4 + 20 = 82.8 → clamped 82.8
        assert!(score >= 80.0, "score={}", score);
        assert_eq!(Severity::from_risk(score), Severity::Critical);
    }

    #[test]
    fn jailbreak_alone_adds_to_risk() {
        let score = composite_score(&RiskInputs {
            max_cvss:             7.5,
            pii_count:            0,
            high_entropy:         false,
            entropy_contribution: 0.0,
            structural_hit:       false,
            jailbreak:            true,
        });
        // 45 + 0 + 0 + 15 = 60
        assert!((score - 60.0).abs() < 0.5, "score={}", score);
    }

    #[test]
    fn clean_text_scores_zero() {
        let score = composite_score(&RiskInputs {
            max_cvss:             0.0,
            pii_count:            0,
            high_entropy:         false,
            entropy_contribution: 0.0,
            structural_hit:       false,
            jailbreak:            false,
        });
        assert_eq!(score, 0.0);
    }

    #[test]
    fn score_clamped_at_100() {
        let score = composite_score(&RiskInputs {
            max_cvss:             10.0,
            pii_count:            10,
            high_entropy:         true,
            entropy_contribution: 30.0,
            structural_hit:       true,
            jailbreak:            true,
        });
        assert_eq!(score, 100.0);
    }
}
