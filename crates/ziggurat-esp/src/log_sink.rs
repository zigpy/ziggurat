//! A `tracing` subscriber that forwards log records to the host as `log` notifications on
//! the JSON API, rather than to a serial console — the USB-Serial-JTAG already carries the
//! protocol, so println-style logging there would corrupt it.

use alloc::string::String;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU8, Ordering};

use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber, span};

use crate::api;

/// Verbosity threshold as a rank; records at or below it are forwarded.
static MAX_LEVEL: AtomicU8 = AtomicU8::new(3);

const fn rank(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 1,
        Level::WARN => 2,
        Level::INFO => 3,
        Level::DEBUG => 4,
        Level::TRACE => 5,
    }
}

/// Set the verbosity threshold from a level name (`off`/`error`/`warn`/`info`/`debug`/
/// `trace`); unknown names are ignored. Returns the level applied, if recognized.
pub fn set_log_level(level: &str) -> Option<&'static str> {
    let rank = match level {
        "off" => 0,
        "error" => 1,
        "warn" => 2,
        "info" => 3,
        "debug" => 4,
        "trace" => 5,
        _ => return None,
    };
    MAX_LEVEL.store(rank, Ordering::Relaxed);
    Some(match rank {
        0 => "off",
        1 => "error",
        2 => "warn",
        3 => "info",
        4 => "debug",
        _ => "trace",
    })
}

pub fn install() {
    let _ = tracing::subscriber::set_global_default(LogSink);
}

struct LogSink;

impl Subscriber for LogSink {
    fn register_callsite(&self, _metadata: &Metadata<'_>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        rank(metadata.level()) <= MAX_LEVEL.load(Ordering::Relaxed)
    }

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();

        let mut message = String::new();
        event.record(&mut MessageVisitor(&mut message));

        api::emit_log(metadata.level().as_str(), metadata.target(), &message);
    }

    // Events-only: spans are not used by the stack, so span bookkeeping is a no-op.
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

/// Collects an event's `message` field (and appends any structured fields) into a string.
struct MessageVisitor<'a>(&'a mut String);

impl Visit for MessageVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}
