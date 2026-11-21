//! Pure, scoped model of Fail2Ban 1.1.1 CommandAction phase ordering.
//!
//! Steps carry no command strings, paths, addresses, or capabilities. The
//! caller supplies only simulated operation availability/outcomes. This
//! covers one common family or distinct family operations; it deliberately
//! omits equality-based deduplication of rendered commands, which requires
//! the original substitution/operation cache. No daemon or actions are wired.

pub(super) use super::legacy_action_policy::Family;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StepKind {
    Start,
    Check,
    Repair,
    Ban,
    Unban,
    Flush,
    Stop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Step {
    pub(super) kind: StepKind,
    pub(super) family: Family,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Inactive,
    Started,
    HasItems,
}

/// An original CommandAction lifecycle independent of command rendering.
#[derive(Debug)]
pub(super) struct Lifecycle {
    start_on_demand: bool,
    start_families: Vec<Family>,
    checks_enabled: bool,
    repair_on_unban: bool,
    states: Vec<(Family, State)>,
}

impl Lifecycle {
    /// `checks_enabled` denotes a configured base `actioncheck`, which gates
    /// both consistency checks and checking after a failed ticket operation.
    pub(super) fn new(
        start_on_demand: bool,
        start_families: Vec<Family>,
        checks_enabled: bool,
        repair_on_unban: bool,
    ) -> Self {
        Self {
            start_on_demand,
            start_families,
            checks_enabled,
            repair_on_unban,
            states: Vec::new(),
        }
    }

    pub(super) fn is_started(&self, family: Family) -> bool {
        self.state(family)
            .is_some_and(|state| state != State::Inactive)
    }

    pub(super) fn has_items(&self, family: Family) -> bool {
        self.state(family) == Some(State::HasItems)
    }

    // FnMut receives a typed phase query and returns None if the operation for
    // this family is absent, otherwise Some with the simulated success result.
    // Missing operations behave like upstream empty definitions, i.e. no
    // command should be recorded and the phase succeeds.
    pub(super) fn start(&mut self, record: &mut impl FnMut(Step) -> Option<bool>) -> bool {
        if self.start_on_demand {
            return true;
        }
        let mut success = true;
        for family in self.start_families.clone() {
            success &= self.start_one(family, record);
        }
        success
    }

    pub(super) fn ban(
        &mut self,
        family: Family,
        record: &mut impl FnMut(Step) -> Option<bool>,
    ) -> bool {
        if self.start_on_demand && !self.is_started(family) && !self.start_one(family, record) {
            return false;
        }
        if !self.process(StepKind::Ban, family, record) {
            return false;
        }
        self.set_state(family, State::HasItems);
        true
    }

    pub(super) fn unban(
        &mut self,
        family: Family,
        record: &mut impl FnMut(Step) -> Option<bool>,
    ) -> bool {
        // This is a coarse flag, not a counter. A successful individual
        // unban does not clear it.
        !self.has_items(family) || self.process(StepKind::Unban, family, record)
    }

    pub(super) fn flush(&mut self, record: &mut impl FnMut(Step) -> Option<bool>) -> bool {
        let mut success = true;
        for (family, state) in &mut self.states {
            if *state == State::HasItems {
                let flushed = phase(record, StepKind::Flush, *family);
                if flushed {
                    *state = State::Started;
                }
                success &= flushed;
            }
        }
        success
    }

    pub(super) fn stop(&mut self, record: &mut impl FnMut(Step) -> Option<bool>) -> bool {
        // Upstream clears all state before attempting any stop. A partial
        // failure does not cause another stop attempt for the failed family.
        let previous = std::mem::take(&mut self.states);
        let mut success = true;
        for (family, state) in previous {
            if state != State::Inactive {
                success &= phase(record, StepKind::Stop, family);
            }
        }
        success
    }

    pub(super) fn consistency_check(
        &mut self,
        record: &mut impl FnMut(Step) -> Option<bool>,
    ) -> bool {
        if !self.checks_enabled {
            return true;
        }
        let mut success = true;
        for (family, previous) in self.states.clone() {
            if previous != State::Inactive && !self.invariant(family, true, true, record) {
                self.set_state(family, State::Inactive);
                success = false;
            }
        }
        success
    }

    fn state(&self, family: Family) -> Option<State> {
        self.states
            .iter()
            .find_map(|&(stored, state)| (stored == family).then_some(state))
    }

    fn set_state(&mut self, family: Family, state: State) {
        if let Some((_, current)) = self.states.iter_mut().find(|(stored, _)| *stored == family) {
            *current = state;
        } else {
            self.states.push((family, state));
        }
    }

    fn start_one(&mut self, family: Family, record: &mut impl FnMut(Step) -> Option<bool>) -> bool {
        if !phase(record, StepKind::Start, family) {
            return false;
        }
        self.set_state(family, State::Started);
        true
    }

    fn process(
        &mut self,
        kind: StepKind,
        family: Family,
        record: &mut impl FnMut(Step) -> Option<bool>,
    ) -> bool {
        if phase(record, kind, family) {
            return true;
        }
        let is_unban = kind == StepKind::Unban;
        if self.checks_enabled
            && !self.invariant(family, !is_unban || self.repair_on_unban, !is_unban, record)
        {
            return false;
        }
        // The operation gets a single retry even without a configured check.
        phase(record, kind, family)
    }

    fn invariant(
        &mut self,
        family: Family,
        allow_repair: bool,
        force_start: bool,
        record: &mut impl FnMut(Step) -> Option<bool>,
    ) -> bool {
        if !force_start && self.state(family).is_none() {
            return true;
        }
        if phase(record, StepKind::Check, family) {
            return true;
        }
        if !allow_repair {
            return false;
        }

        match record(Step {
            kind: StepKind::Repair,
            family,
        }) {
            Some(true) => self.set_state(family, State::Started),
            Some(false) => {
                self.set_state(family, State::Inactive);
                return false;
            }
            None => {
                // If there is no explicit repair, restart. Upstream tolerates
                // a failed stop and still attempts to recover through start.
                if self.state(family).is_some() {
                    self.set_state(family, State::Inactive);
                    let _ = phase(record, StepKind::Stop, family);
                }
                if (force_start || !self.start_on_demand) && !self.start_one(family, record) {
                    return false;
                }
            }
        }
        !self.is_started(family) || phase(record, StepKind::Check, family)
    }
}

fn phase(record: &mut impl FnMut(Step) -> Option<bool>, kind: StepKind, family: Family) -> bool {
    record(Step { kind, family }).unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Outcome = (StepKind, Family, Option<bool>);

    fn verify(
        expected: &[Outcome],
        run: impl FnOnce(&mut dyn FnMut(Step) -> Option<bool>) -> bool,
    ) -> bool {
        let mut steps = expected.iter();
        let success = run(&mut |step| {
            let expected = steps.next();
            assert!(expected.is_some(), "unexpected step: {step:?}");
            let Some(&(kind, family, outcome)) = expected else {
                return Some(false);
            };
            assert_eq!(step, Step { kind, family });
            outcome
        });
        assert!(steps.next().is_none(), "missed a step");
        success
    }

    #[test]
    fn on_demand_start_and_teardown_follow_actual_start_order() {
        use Family::{Ipv4, Ipv6};
        use StepKind::{Ban, Flush, Start, Stop, Unban};

        let mut action = Lifecycle::new(true, vec![Ipv4, Ipv6], true, false);
        assert!(verify(&[], |mut f| action.start(&mut f)));
        assert!(verify(&[], |mut f| action.unban(Ipv6, &mut f)));
        assert!(verify(
            &[(Start, Ipv6, Some(true)), (Ban, Ipv6, Some(true))],
            |mut f| action.ban(Ipv6, &mut f)
        ));
        assert!(verify(
            &[(Start, Ipv4, Some(true)), (Ban, Ipv4, Some(true))],
            |mut f| action.ban(Ipv4, &mut f)
        ));
        assert!(verify(&[(Unban, Ipv6, Some(true))], |mut f| {
            action.unban(Ipv6, &mut f)
        }));
        assert!(action.has_items(Ipv6));
        assert!(!verify(
            &[(Flush, Ipv6, Some(false)), (Flush, Ipv4, Some(true))],
            |mut f| action.flush(&mut f)
        ));
        assert!(action.has_items(Ipv6));
        assert!(!action.has_items(Ipv4));
        assert!(!verify(
            &[(Stop, Ipv6, Some(false)), (Stop, Ipv4, Some(true))],
            |mut f| action.stop(&mut f)
        ));
        assert!(verify(&[], |mut f| action.stop(&mut f)));
    }

    #[test]
    fn lazy_start_failure_aborts_ban_and_empty_start_is_success() {
        use Family::Common;
        use StepKind::{Ban, Start};

        let mut action = Lifecycle::new(true, vec![Common], true, false);
        assert!(!verify(&[(Start, Common, Some(false))], |mut f| {
            action.ban(Common, &mut f)
        }));
        assert!(!action.is_started(Common));
        assert!(verify(
            &[(Start, Common, None), (Ban, Common, None)],
            |mut f| { action.ban(Common, &mut f) }
        ));
        assert!(action.has_items(Common));
    }

    #[test]
    fn ban_repairs_only_after_failed_attempt_and_checks_after_repair() {
        use Family::Common;
        use StepKind::{Ban, Check, Repair, Start};

        let mut action = Lifecycle::new(false, vec![Common], true, false);
        assert!(verify(&[(Start, Common, Some(true))], |mut f| action.start(&mut f)));
        assert!(verify(
            &[
                (Ban, Common, Some(false)),
                (Check, Common, Some(false)),
                (Repair, Common, Some(true)),
                (Check, Common, Some(true)),
                (Ban, Common, Some(true)),
            ],
            |mut f| action.ban(Common, &mut f)
        ));
        assert!(action.has_items(Common));
        assert!(!verify(
            &[
                (Ban, Common, Some(false)),
                (Check, Common, Some(false)),
                (Repair, Common, Some(true)),
                (Check, Common, Some(false)),
            ],
            |mut f| action.ban(Common, &mut f)
        ));
        assert!(action.is_started(Common));
        assert!(!action.has_items(Common));
        assert!(!verify(
            &[(Check, Common, Some(false)), (Repair, Common, Some(false))],
            |mut f| action.consistency_check(&mut f)
        ));
        assert!(!action.is_started(Common));
    }

    #[test]
    fn retries_without_check_and_handles_absent_repair_by_restarting() {
        use Family::Common;
        use StepKind::{Ban, Check, Repair, Start, Stop};

        let mut no_check = Lifecycle::new(false, vec![Common], false, false);
        assert!(verify(
            &[(Ban, Common, Some(false)), (Ban, Common, Some(true))],
            |mut f| no_check.ban(Common, &mut f)
        ));

        let mut action = Lifecycle::new(true, vec![Common], true, false);
        assert!(verify(
            &[
                (Start, Common, Some(true)),
                (Ban, Common, Some(false)),
                (Check, Common, Some(false)),
                (Repair, Common, None),
                (Stop, Common, Some(false)),
                (Start, Common, Some(true)),
                (Check, Common, Some(true)),
                (Ban, Common, Some(true)),
            ],
            |mut f| action.ban(Common, &mut f)
        ));
    }

    #[test]
    fn repairing_a_failed_unban_is_opt_in() {
        use Family::Common;
        use StepKind::{Ban, Check, Repair, Unban};

        for repair_on_unban in [false, true] {
            let mut action = Lifecycle::new(false, vec![Common], true, repair_on_unban);
            assert!(verify(&[(Ban, Common, Some(true))], |mut f| action
                .ban(Common, &mut f)));
            let mut steps = vec![(Unban, Common, Some(false)), (Check, Common, Some(false))];
            if repair_on_unban {
                steps.extend([
                    (Repair, Common, Some(true)),
                    (Check, Common, Some(true)),
                    (Unban, Common, Some(true)),
                ]);
            }
            assert_eq!(
                verify(&steps, |mut f| action.unban(Common, &mut f)),
                repair_on_unban
            );
            assert_eq!(action.has_items(Common), !repair_on_unban);
        }
    }
}
