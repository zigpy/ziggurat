//! A `tracing` subscriber that writes log records to the UART.

use alloc::string::String;
use core::fmt::{self, Write};

use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber, span};

use crate::LOG_OUTBOUND;

const MAX_LEVEL: Level = Level::DEBUG;

pub fn install() {
    let _ = tracing::subscriber::set_global_default(LogSink);
}

struct LogSink;

impl Subscriber for LogSink {
    fn register_callsite(&self, _metadata: &Metadata<'_>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        *metadata.level() <= MAX_LEVEL
    }

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();

        let mut line = String::new();
        let _ = write!(line, "{} {}: ", metadata.level().as_str(), metadata.target());
        event.record(&mut MessageVisitor(&mut line));

        let _ = LOG_OUTBOUND.try_send(line);
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
