//! BackOtter: the warnings and errors the unit tests log, for the tests of
//! what a restore says (ForkAudit1 G6-02, G6-03; `osattrs`' casefolding on
//! FAT): one logger for the test
//! binary, whose tests run on threads of one process, so that a test looks
//! for lines with a name only it uses.

use std::sync::{Mutex, Once, PoisonError};

use log::{Level, LevelFilter, Log, Metadata, Record};

/// The lines logged at `Warn` and above, since [`capture`].
static LINES: Mutex<Vec<(Level, String)>> = Mutex::new(Vec::new());

struct Capture;

impl Log for Capture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= Level::Warn
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            LINES
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((record.level(), record.args().to_string()));
        }
    }

    fn flush(&self) {}
}

/// Keeps what is logged at `Warn` and above from now on, for [`lines`].
pub(crate) fn capture() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        log::set_logger(&Capture).expect("the unit tests set no other logger");
        log::set_max_level(LevelFilter::Warn);
    });
}

/// The lines kept so far that contain `needle`, each with its level, in
/// the order they were logged.
pub(crate) fn lines(needle: &str) -> Vec<(Level, String)> {
    LINES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(_, line)| line.contains(needle))
        .cloned()
        .collect()
}
