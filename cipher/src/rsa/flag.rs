use std::sync::atomic::{AtomicBool, Ordering};

pub(super) struct FlagClear<'a> {
    pub(super) is_working: &'a AtomicBool,
}

impl<'a> Drop for FlagClear<'a> {
    fn drop(&mut self) {
        self.is_working.store(false, Ordering::Release);
    }
}
