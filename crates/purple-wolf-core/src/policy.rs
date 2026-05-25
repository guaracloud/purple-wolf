//! Request decision logic: resolves detector verdicts into an allow/block action.
use crate::config::{GroupMode, Mode};
use crate::detectors::{Group, Verdict};

/// Outcome of a single request inspection: pass through or block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The request is permitted to proceed.
    Allow,
    /// The request is blocked and should receive an error response.
    Block,
}

/// The final decision for one request.
#[derive(Debug)]
pub struct Decision {
    /// Whether to allow or block the request.
    pub action: Action,
    /// The verdict that caused a block, if any.
    pub blocked_by: Option<Verdict>,
    /// Verdicts seen but not enforced (monitor mode) — for audit logging.
    pub would_block: Vec<Verdict>,
}

/// Resolve verdicts into an action.
///
/// `global` is the global mode. `group_mode` maps a group to its effective
/// mode. A verdict blocks only when BOTH the global mode and the group mode
/// enforce.
///
/// When multiple enforced verdicts could block, the highest-severity one
/// wins the `blocked_by` slot; the rest go to `would_block`. This makes the
/// audit-log `blocked_rule` name the most serious finding rather than
/// whichever detector iterated first — important for SIEM triage and for
/// post-incident review.
pub fn decide(
    verdicts: Vec<Verdict>,
    global: Mode,
    group_mode: impl Fn(Group) -> GroupMode,
) -> Decision {
    // Partition by enforcement so we can pick the worst enforced verdict.
    let mut enforced_pool: Vec<Verdict> = Vec::new();
    let mut would_block: Vec<Verdict> = Vec::new();
    for v in verdicts {
        let gm = group_mode(v.group);
        if gm == GroupMode::Off {
            continue;
        }
        if global == Mode::Enforce && gm == GroupMode::Enforce {
            enforced_pool.push(v);
        } else {
            would_block.push(v);
        }
    }

    // Highest severity wins; on a tie, first one in iteration order (stable).
    // We pop the chosen verdict out and demote the rest to `would_block`.
    let blocked_by = if enforced_pool.is_empty() {
        None
    } else {
        // index of max severity; ties go to the lowest index (first detector)
        let mut idx = 0usize;
        for (i, v) in enforced_pool.iter().enumerate().skip(1) {
            if v.severity > enforced_pool[idx].severity {
                idx = i;
            }
        }
        let chosen = enforced_pool.swap_remove(idx);
        // Anything that didn't win is treated as a non-blocking signal.
        would_block.append(&mut enforced_pool);
        Some(chosen)
    };

    Decision {
        action: if blocked_by.is_some() {
            Action::Block
        } else {
            Action::Allow
        },
        blocked_by,
        would_block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::Severity;

    fn verdict(group: Group) -> Verdict {
        Verdict {
            group,
            rule: "t",
            severity: Severity::High,
            detail: "d".into(),
        }
    }

    #[test]
    fn blocks_when_global_and_group_enforce() {
        let d = decide(vec![verdict(Group::Injection)], Mode::Enforce, |_| {
            GroupMode::Enforce
        });
        assert_eq!(d.action, Action::Block);
        assert!(d.blocked_by.is_some());
    }

    #[test]
    fn monitor_global_never_blocks() {
        let d = decide(vec![verdict(Group::Injection)], Mode::Monitor, |_| {
            GroupMode::Enforce
        });
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.would_block.len(), 1);
    }

    #[test]
    fn group_mode_off_is_ignored() {
        let d = decide(vec![verdict(Group::Injection)], Mode::Enforce, |_| {
            GroupMode::Off
        });
        assert_eq!(d.action, Action::Allow);
        assert!(d.would_block.is_empty());
    }

    fn verdict_sev(group: Group, sev: Severity, rule: &'static str) -> Verdict {
        Verdict {
            group,
            rule,
            severity: sev,
            detail: "d".into(),
        }
    }

    /// Regression guard for NEW-H1: when multiple enforced verdicts compete
    /// for the `blocked_by` slot, the highest-severity one wins regardless
    /// of detector iteration order. Pre-fix this assertion failed: the
    /// `scanner_ua` Medium verdict ran first (Signatures group) and pushed
    /// the Critical `sqli` into `would_block`.
    #[test]
    fn highest_severity_verdict_wins_blocked_by() {
        let verdicts = vec![
            verdict_sev(Group::Signatures, Severity::Medium, "scanner_ua"),
            verdict_sev(Group::Injection, Severity::Critical, "sqli"),
        ];
        let d = decide(verdicts, Mode::Enforce, |_| GroupMode::Enforce);
        assert_eq!(d.action, Action::Block);
        let chosen = d.blocked_by.expect("must block");
        assert_eq!(chosen.rule, "sqli");
        assert_eq!(chosen.severity, Severity::Critical);
        // The demoted Medium verdict shows up in would_block, not lost.
        assert_eq!(d.would_block.len(), 1);
        assert_eq!(d.would_block[0].rule, "scanner_ua");
    }

    #[test]
    fn ties_break_in_first_iteration_order() {
        // Two equally-Critical verdicts — first one in the list wins.
        let verdicts = vec![
            verdict_sev(Group::Injection, Severity::Critical, "sqli"),
            verdict_sev(Group::Signatures, Severity::Critical, "lfi"),
        ];
        let d = decide(verdicts, Mode::Enforce, |_| GroupMode::Enforce);
        let chosen = d.blocked_by.expect("must block");
        assert_eq!(chosen.rule, "sqli");
    }

    #[test]
    fn monitor_verdicts_never_promoted_even_if_more_severe() {
        // A Critical verdict from a Monitor-mode group must NOT block; an
        // Enforce-mode Medium beside it must win.
        let verdicts = vec![
            verdict_sev(Group::Injection, Severity::Critical, "sqli"),
            verdict_sev(Group::Signatures, Severity::Medium, "scanner_ua"),
        ];
        let d = decide(verdicts, Mode::Enforce, |g| match g {
            Group::Injection => GroupMode::Monitor,
            _ => GroupMode::Enforce,
        });
        let chosen = d.blocked_by.expect("must block");
        assert_eq!(chosen.rule, "scanner_ua");
        assert!(d
            .would_block
            .iter()
            .any(|v| v.rule == "sqli" && v.severity == Severity::Critical));
    }
}
