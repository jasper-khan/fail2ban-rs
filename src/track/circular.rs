//! Fixed-size ring buffer for failure timestamps.
//!
//! Capacity equals `max_retry`. When the buffer is full and the span from
//! earliest to latest event is within `find_time`, a ban threshold is reached.
//! Retention follows arrival order even when timestamps from different files
//! arrive out of order. Threshold checks are O(1) in chronological order.

/// A fixed-capacity ring buffer of `i64` unix timestamps.
#[derive(Debug, Clone)]
pub struct CircularTimestamps {
    buf: Vec<i64>,
    /// Points to the first arrival retained when the buffer is full.
    head: usize,
    len: usize,
    /// Adjacent event-time reversals in arrival order. Zero allows using the endpoints.
    inversions: usize,
}

impl CircularTimestamps {
    /// Create a new buffer with the given capacity (typically `max_retry`).
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0; capacity],
            head: 0,
            len: 0,
            inversions: 0,
        }
    }

    /// Push a timestamp, overwriting the earliest arrival if full.
    pub fn push(&mut self, ts: i64) {
        let cap = self.buf.len();
        if cap == 0 {
            return;
        }
        if cap > 1 {
            if self.len == cap && self.buf.get(self.head) > self.buf.get((self.head + 1) % cap) {
                self.inversions -= 1;
            }
            if self.last_arrival().is_some_and(|last| last > ts) {
                self.inversions += 1;
            }
        }
        let write_pos = if self.len < cap {
            self.len
        } else {
            let pos = self.head;
            self.head = (self.head + 1) % cap;
            pos
        };
        if let Some(slot) = self.buf.get_mut(write_pos) {
            *slot = ts;
        }
        if self.len < cap {
            self.len += 1;
        }
    }

    /// Returns `true` when the buffer has reached its capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len == self.buf.len()
    }

    /// Earliest retained event timestamp (not necessarily the first arrival).
    #[must_use]
    pub fn oldest(&self) -> Option<i64> {
        self.bounds().map(|(earliest, _)| earliest)
    }

    /// Latest retained event timestamp (not necessarily the last arrival).
    #[must_use]
    pub fn newest(&self) -> Option<i64> {
        self.bounds().map(|(_, latest)| latest)
    }

    fn last_arrival(&self) -> Option<i64> {
        if self.len == 0 {
            return None;
        }
        let cap = self.buf.len();
        let idx = if self.len < cap {
            self.len - 1
        } else {
            (self.head + cap - 1) % cap
        };
        self.buf.get(idx).copied()
    }

    fn bounds(&self) -> Option<(i64, i64)> {
        let first = self.buf.get(self.head).copied().filter(|_| self.len != 0)?;
        if self.inversions == 0 {
            return Some((first, self.last_arrival()?));
        }
        // For a full ring the physical order is irrelevant to the extrema;
        // for a partial one, the initialized entries are its first len slots.
        Some(
            self.buf
                .iter()
                .take(self.len)
                .fold((first, first), |(earliest, latest), &ts| {
                    (earliest.min(ts), latest.max(ts))
                }),
        )
    }

    /// Check if the failure threshold is reached: buffer is full and the
    /// time span from oldest to newest is within `find_time` seconds.
    ///
    /// The window is inclusive: a span of exactly `find_time` counts, so
    /// failures spanning precisely the configured window still trigger a ban.
    #[must_use]
    pub fn threshold_reached(&self, find_time: i64) -> bool {
        if !self.is_full() {
            return false;
        }
        self.bounds().is_some_and(|(earliest, latest)| {
            i128::from(latest) - i128::from(earliest) <= i128::from(find_time)
        })
    }

    /// Number of timestamps currently stored.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The total capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
#[path = "circular_test.rs"]
mod circular_test;
