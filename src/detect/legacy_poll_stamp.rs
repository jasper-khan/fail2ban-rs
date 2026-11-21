//! Original Fail2Ban 1.1.1 polling stamp selection, without file operations.
//!
//! Slot indices refer to the immutable registration order. A complete sample
//! snapshot is validated before successful stamps and per-slot miss streaks
//! are committed. Synthetic ENOENT preserves the last successful stamp
//! until the 51st consecutive miss deregisters the slot.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct PollStamp {
    /// Python-compatible `st_mtime` seconds (not a nanosecond timestamp).
    pub(crate) mtime: f64,
    pub(crate) inode: u64,
    pub(crate) size: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SnapshotError {
    Foreign(usize),
    Deregistered(usize),
    Duplicate(usize),
    Missing(usize),
    NonFiniteMtime(usize),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Foreign(index) => write!(f, "unregistered polling snapshot slot {index}"),
            Self::Deregistered(index) => write!(f, "removed polling snapshot slot {index}"),
            Self::Duplicate(index) => write!(f, "duplicate polling snapshot slot {index}"),
            Self::Missing(index) => write!(f, "missing polling snapshot slot {index}"),
            Self::NonFiniteMtime(index) => {
                write!(
                    f,
                    "non-finite modification time for polling snapshot slot {index}"
                )
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

#[derive(Debug)]
pub(crate) struct PollSelection {
    slots: Vec<Option<Slot>>,
}

const REMOVE_AFTER: u8 = 50;

#[derive(Clone, Copy, Debug, Default)]
struct Slot {
    previous: Option<PollStamp>,
    missing_streak: u8,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Selections {
    pub(crate) changed: Vec<usize>,
    pub(crate) removed: Vec<usize>,
}

#[derive(Clone, Copy)]
enum Sample {
    Omitted,
    Absent,
    Found(PollStamp),
}

impl PollSelection {
    pub(crate) fn new(slot_count: usize) -> Self {
        Self {
            // Original starts with an unobserved stamp for each registered
            // path, including zero-byte files with mtime zero.
            slots: vec![Some(Slot::default()); slot_count],
        }
    }

    /// Return changed slots in registration order. Rows may be presented in
    /// any order, but there must be exactly one finite stamp per slot. An
    /// invalid snapshot never alters any previous stamp.
    pub(crate) fn select(
        &mut self,
        snapshot: &[(usize, PollStamp)],
    ) -> Result<Vec<usize>, SnapshotError> {
        let samples = snapshot
            .iter()
            .map(|&(index, stamp)| (index, Some(stamp)))
            .collect::<Vec<_>>();
        self.select_sampled(&samples)
    }

    /// None represents one sampled ENOENT, not a missing row. Preserve that
    /// slot's previous stamp (including an unobserved first stamp), so a
    /// reappearing identical tuple is not selected. Omitted/duplicate slots
    /// or invalid mtime still reject the whole snapshot.
    pub(crate) fn select_sampled(
        &mut self,
        snapshot: &[(usize, Option<PollStamp>)],
    ) -> Result<Vec<usize>, SnapshotError> {
        self.select_sampled_with_removals(snapshot)
            .map(|result| result.changed)
    }

    /// All registered slots are required; removed slots must be omitted.
    /// Reset the miss count on every successful stat, even unchanged.
    /// Return removals and changed streams in registration order before
    /// the caller drains any streams. No jail-wide failure counter or idle
    /// state is modeled.
    pub(crate) fn select_sampled_with_removals(
        &mut self,
        snapshot: &[(usize, Option<PollStamp>)],
    ) -> Result<Selections, SnapshotError> {
        self.select_sampled_with_errors(snapshot, |_| {})
    }

    /// Charge each synthetic stat error in registration order, after complete
    /// snapshot validation and before handling that source's removal.
    pub(crate) fn select_sampled_with_errors(
        &mut self,
        snapshot: &[(usize, Option<PollStamp>)],
        mut stat_error: impl FnMut(usize),
    ) -> Result<Selections, SnapshotError> {
        let mut current = vec![Sample::Omitted; self.slots.len()];
        for &(index, stamp) in snapshot {
            let slot = current
                .get_mut(index)
                .ok_or(SnapshotError::Foreign(index))?;
            if !self.is_registered(index) {
                return Err(SnapshotError::Deregistered(index));
            }
            if !matches!(slot, Sample::Omitted) {
                return Err(SnapshotError::Duplicate(index));
            }
            if stamp.is_some_and(|stamp| !stamp.mtime.is_finite()) {
                return Err(SnapshotError::NonFiniteMtime(index));
            }
            *slot = stamp.map_or(Sample::Absent, Sample::Found);
        }
        if let Some(index) = self
            .slots
            .iter()
            .zip(&current)
            .position(|(slot, sample)| slot.is_some() && matches!(sample, Sample::Omitted))
        {
            return Err(SnapshotError::Missing(index));
        }

        let mut selected = Selections::default();
        for (index, (slot, sample)) in self.slots.iter_mut().zip(current).enumerate() {
            let Some(active) = slot else {
                continue;
            };
            match sample {
                Sample::Found(stamp) => {
                    active.missing_streak = 0;
                    if active.previous != Some(stamp) {
                        active.previous = Some(stamp);
                        selected.changed.push(index);
                    }
                }
                Sample::Absent => {
                    active.missing_streak += 1;
                    stat_error(index);
                    if active.missing_streak > REMOVE_AFTER {
                        *slot = None;
                        selected.removed.push(index);
                    }
                }
                Sample::Omitted => {}
            }
        }
        Ok(selected)
    }

    pub(crate) fn is_registered(&self, index: usize) -> bool {
        self.slots.get(index).is_some_and(Option::is_some)
    }

    pub(crate) fn missing_streak(&self, index: usize) -> Option<u8> {
        self.slots
            .get(index)?
            .as_ref()
            .map(|slot| slot.missing_streak)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(mtime: f64, inode: u64, size: u64) -> PollStamp {
        PollStamp { mtime, inode, size }
    }

    #[test]
    fn first_empty_file_is_changed_then_initial_observation_is_committed() {
        let mut model = PollSelection::new(1);
        let snapshot = [(0, stamp(0.0, 0, 0))];
        assert_eq!(model.select(&snapshot), Ok(vec![0]));
        assert_eq!(model.select(&snapshot), Ok(vec![]));
        assert_eq!(PollSelection::new(0).select(&[]), Ok(vec![]));
    }

    #[test]
    fn any_single_original_stamp_component_can_mark_a_slot_changed() {
        let mut model = PollSelection::new(1);
        for current in [
            stamp(100.0, 7, 12),
            stamp(100.5, 7, 12), // mtime only
            stamp(100.5, 8, 12), // inode only
            stamp(100.5, 8, 13), // size only
            stamp(99.0, 8, 13),  // even a backwards mtime
        ] {
            let snapshot = [(0, current)];
            assert_eq!(model.select(&snapshot), Ok(vec![0]));
            assert_eq!(model.select(&snapshot), Ok(vec![]));
        }
    }

    #[test]
    fn registration_order_is_independent_of_snapshot_order() {
        let mut model = PollSelection::new(3);
        let baseline = [
            (2, stamp(10.0, 3, 6)),
            (0, stamp(10.0, 1, 4)),
            (1, stamp(10.0, 2, 5)),
        ];
        assert_eq!(model.select(&baseline), Ok(vec![0, 1, 2]));
        let next = [
            (2, stamp(10.0, 3, 7)),
            (1, stamp(10.0, 2, 5)),
            (0, stamp(10.0, 1, 9)),
        ];
        assert_eq!(model.select(&next), Ok(vec![0, 2]));
        assert_eq!(model.select(&next), Ok(vec![])); // All committed before drain.
    }

    #[test]
    fn malformed_snapshot_does_not_partially_commit() {
        let baseline = [(0, stamp(10.0, 1, 4)), (1, stamp(10.0, 2, 5))];
        let changed = stamp(12.0, 1, 4);
        let mut model = PollSelection::new(2);
        assert_eq!(model.select(&baseline), Ok(vec![0, 1]));

        for (malformed, error) in [
            (
                vec![(0, changed), (0, changed)],
                SnapshotError::Duplicate(0),
            ),
            (vec![(0, changed), (2, changed)], SnapshotError::Foreign(2)),
            (vec![(0, changed)], SnapshotError::Missing(1)),
            (
                vec![(0, changed), (1, stamp(f64::NAN, 2, 5))],
                SnapshotError::NonFiniteMtime(1),
            ),
            (
                vec![(0, changed), (1, stamp(f64::INFINITY, 2, 5))],
                SnapshotError::NonFiniteMtime(1),
            ),
        ] {
            assert_eq!(model.select(&malformed), Err(error));
            assert_eq!(model.select(&baseline), Ok(vec![]));
        }
        assert_eq!(
            model.select(&[(1, stamp(10.0, 2, 5)), (0, changed)]),
            Ok(vec![0])
        );
    }

    #[test]
    fn modification_time_compares_numerically() {
        let mut model = PollSelection::new(1);
        assert_eq!(model.select(&[(0, stamp(-0.0, 1, 0))]), Ok(vec![0]));
        assert_eq!(model.select(&[(0, stamp(0.0, 1, 0))]), Ok(vec![]));
        assert_eq!(
            model.select(&[(0, stamp(f64::from_bits(1), 1, 0))]),
            Ok(vec![0])
        );
    }

    #[test]
    fn sampled_absence_preserves_unobserved_and_last_successful_stamps() {
        let left = stamp(10.0, 1, 4);
        let right = stamp(10.0, 2, 5);
        let changed = stamp(11.0, 1, 4);
        let mut model = PollSelection::new(2);
        assert_eq!(
            model.select_sampled(&[(1, Some(right)), (0, None)]),
            Ok(vec![1])
        );
        assert_eq!(model.select_sampled(&[(0, None), (1, None)]), Ok(vec![]));
        assert_eq!(
            model.select_sampled(&[(1, Some(right)), (0, Some(left))]),
            Ok(vec![0])
        );
        assert_eq!(
            model.select_sampled(&[(0, None), (1, Some(right))]),
            Ok(vec![])
        );
        assert_eq!(
            model.select_sampled(&[(0, Some(left)), (1, Some(right))]),
            Ok(vec![])
        );
        assert_eq!(
            model.select_sampled(&[(0, Some(changed)), (1, None)]),
            Ok(vec![0])
        );
    }

    #[test]
    fn omitted_and_duplicate_missing_rows_are_transactional_errors() {
        let mut model = PollSelection::new(2);
        let left = stamp(10.0, 1, 4);
        let right = stamp(10.0, 2, 5);
        let newer = stamp(11.0, 1, 4);
        let baseline = [(0, Some(left)), (1, Some(right))];
        assert_eq!(model.select_sampled(&baseline), Ok(vec![0, 1]));
        assert_eq!(
            model.select_sampled(&[(0, Some(newer))]),
            Err(SnapshotError::Missing(1))
        );
        for duplicate in [None, Some(right)] {
            assert_eq!(
                model.select_sampled(&[(0, Some(newer)), (1, None), (1, duplicate)]),
                Err(SnapshotError::Duplicate(1))
            );
        }
        assert_eq!(model.select_sampled(&baseline), Ok(vec![]));
        assert_eq!(
            model.select_sampled(&[(0, Some(newer)), (1, None)]),
            Ok(vec![0])
        );
    }

    #[test]
    fn fifty_misses_are_retained_and_identical_success_resets_the_streak() {
        let original = stamp(10.0, 1, 4);
        let peer = stamp(10.0, 2, 8);
        let changed_peer = stamp(11.0, 2, 8);
        let mut model = PollSelection::new(2);
        assert_eq!(model.select(&[(0, original), (1, peer)]), Ok(vec![0, 1]));
        for streak in 1..=50 {
            assert_eq!(
                model.select_sampled_with_removals(&[(1, Some(peer)), (0, None)]),
                Ok(Selections::default())
            );
            assert_eq!(model.missing_streak(0), Some(streak));
        }
        assert_eq!(
            model.select_sampled_with_removals(&[(0, None)]),
            Err(SnapshotError::Missing(1))
        );
        assert_eq!(model.missing_streak(0), Some(50));
        assert_eq!(
            model.select_sampled_with_removals(&[(0, Some(original)), (1, Some(peer))]),
            Ok(Selections::default())
        );
        assert_eq!(model.missing_streak(0), Some(0));
        for _ in 0..50 {
            assert_eq!(
                model.select_sampled_with_removals(&[(0, None), (1, Some(peer))]),
                Ok(Selections::default())
            );
        }
        assert_eq!(
            model.select_sampled_with_removals(&[(1, Some(changed_peer)), (0, None)]),
            Ok(Selections {
                changed: vec![1],
                removed: vec![0]
            })
        );
        assert!(!model.is_registered(0));
        assert_eq!(model.missing_streak(0), None);
        assert_eq!(model.missing_streak(1), Some(0));
        assert_eq!(
            model.select_sampled(&[(0, Some(original)), (1, Some(changed_peer))]),
            Err(SnapshotError::Deregistered(0))
        );
        assert_eq!(model.select(&[(1, changed_peer)]), Ok(vec![]));
    }

    #[test]
    fn removed_slots_do_not_make_empty_snapshots_incomplete() {
        let mut model = PollSelection::new(1);
        for _ in 0..50 {
            assert_eq!(model.select_sampled(&[(0, None)]), Ok(vec![]));
        }
        assert_eq!(
            model.select_sampled_with_removals(&[(0, None)]),
            Ok(Selections {
                changed: vec![],
                removed: vec![0]
            })
        );
        assert_eq!(model.select(&[]), Ok(vec![]));
        assert_eq!(
            model.select_sampled(&[(0, None)]),
            Err(SnapshotError::Deregistered(0))
        );
    }

    #[test]
    fn validated_misses_charge_in_registration_order_including_eviction() {
        let mut model = PollSelection::new(3);
        let stamp = stamp(10.0, 3, 8);
        let mut charges = Vec::new();
        let invalid =
            model.select_sampled_with_errors(&[(0, None), (1, None)], |slot| charges.push(slot));
        assert_eq!(invalid, Err(SnapshotError::Missing(2)));
        assert!(charges.is_empty());
        for _ in 0..50 {
            model
                .select_sampled_with_removals(&[(0, None), (1, Some(stamp)), (2, None)])
                .expect("setup misses");
        }
        let selection = model
            .select_sampled_with_errors(&[(2, None), (1, Some(stamp)), (0, None)], |slot| {
                charges.push(slot);
            })
            .expect("valid ordered scan");
        assert_eq!(charges, [0, 2]);
        assert_eq!(selection.removed, [0, 2]);
    }
}
