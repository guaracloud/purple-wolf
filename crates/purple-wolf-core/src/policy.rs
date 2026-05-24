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
/// mode (already resolved against per-host/path overrides by `rules.rs`).
/// A verdict blocks only when BOTH the global mode and the group mode enforce.
pub fn decide(
    verdicts: Vec<Verdict>,
    global: Mode,
    group_mode: impl Fn(Group) -> GroupMode,
) -> Decision {
    let mut blocked_by = None;
    let mut would_block = Vec::new();

    for v in verdicts {
        let gm = group_mode(v.group);
        if gm == GroupMode::Off {
            continue;
        }
        let enforced = global == Mode::Enforce && gm == GroupMode::Enforce;
        if enforced && blocked_by.is_none() {
            blocked_by = Some(v);
        } else {
            would_block.push(v);
        }
    }

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
}
