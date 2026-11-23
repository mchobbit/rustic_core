//! BackOtter: the budget of pack data a restore holds at once
//! ([`ByteBudget`]), so that a small machine isn't out of memory.

use std::sync::{Condvar, Mutex, PoisonError};

/// BackOtter: the bytes of pack data [`super::restore_contents`] may hold at
/// once ([`super::constants::MAX_RESTORE_BYTES_IN_FLIGHT`]).
#[derive(Debug)]
pub(super) struct ByteBudget {
    total: u64,
    free: Mutex<u64>,
    freed: Condvar,
}

impl ByteBudget {
    pub(super) const fn new(total: u64) -> Self {
        Self {
            total,
            free: Mutex::new(total),
            freed: Condvar::new(),
        }
    }

    /// Waits until `bytes` are free and takes them, until the guard is
    /// dropped. More than the whole budget takes the whole budget: such a
    /// pack goes alone rather than never.
    ///
    /// Only the thread that spawns the restore's tasks may wait here, never
    /// one of the pool's: the bytes are given back by the pool's tasks, which
    /// must be free to run.
    pub(super) fn acquire(&self, bytes: u64) -> BudgetGuard<'_> {
        let bytes = bytes.min(self.total);
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        while *free < bytes {
            free = self
                .freed
                .wait(free)
                .unwrap_or_else(PoisonError::into_inner);
        }
        *free -= bytes;
        drop(free);
        BudgetGuard {
            budget: self,
            bytes,
        }
    }
}

/// Bytes taken from a [`ByteBudget`], given back on drop (a panic or an early
/// return too).
#[derive(Debug)]
pub(super) struct BudgetGuard<'a> {
    budget: &'a ByteBudget,
    bytes: u64,
}

impl Drop for BudgetGuard<'_> {
    fn drop(&mut self) {
        *self
            .budget
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner) += self.bytes;
        self.budget.freed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RustAudit1 R5-16: the budget of bytes in flight gives out no more
    /// than it has, makes a taker wait until enough is given back (by the
    /// drop of a guard, in a panic's unwinding too), and gives a taker of
    /// more than the whole budget the whole of it, alone.
    #[test]
    fn byte_budget_waits_and_gives_back() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

        let free = |budget: &ByteBudget| *budget.free.lock().unwrap_or_else(PoisonError::into_inner);
        let budget = ByteBudget::new(10);
        let first = budget.acquire(8);
        assert_eq!(free(&budget), 2);
        let got = AtomicBool::new(false);
        std::thread::scope(|s| {
            let waiter = s.spawn(|| {
                let guard = budget.acquire(5);
                got.store(true, AtomicOrdering::SeqCst);
                guard.bytes
            });
            // 5 of 2 free: it waits until the 8 are given back.
            std::thread::sleep(std::time::Duration::from_millis(100));
            assert!(!got.load(AtomicOrdering::SeqCst), "5 bytes taken of 2 free");
            drop(first);
            assert_eq!(waiter.join().unwrap(), 5);
        });
        assert!(got.load(AtomicOrdering::SeqCst));
        assert_eq!(free(&budget), 10, "the waiter's guard gave its bytes back");

        // More than the whole budget: the whole budget, once it is free.
        let all = budget.acquire(100);
        assert_eq!((all.bytes, free(&budget)), (10, 0));
        drop(all);

        // A guard dropped by a panic's unwinding gives its bytes back.
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = budget.acquire(7);
            panic!("a write task panics, holding 7 bytes");
        }));
        assert!(unwound.is_err());
        assert_eq!(free(&budget), 10);
    }
}
