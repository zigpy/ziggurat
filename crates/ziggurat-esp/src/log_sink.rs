//! A `tracing` subscriber that writes log records to the UART.

use core::fmt::{self, Write};
use core::mem;

use heapless::Vec;
use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber, span};

use crate::{LOG_CHUNK, LOG_OUTBOUND};

const MAX_LEVEL: Level = Level::INFO;

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

        let mut writer = ChunkWriter::new();
        let _ = write!(
            writer,
            "{} {}: ",
            metadata.level().as_str(),
            metadata.target()
        );
        event.record(&mut MessageVisitor(&mut writer));
        writer.finish();
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

/// Formats bytes into fixed-size inline chunks, spilling each to `LOG_OUTBOUND` as it
/// fills. A single log line therefore streams out as several chunks with no heap
/// allocation. Under backpressure (channel full) the rest of the line is dropped —
/// logging must never block or panic the stack.
struct ChunkWriter {
    buf: Vec<u8, LOG_CHUNK>,
    dropped: bool,
}

impl ChunkWriter {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            dropped: false,
        }
    }

    fn push_bytes(&mut self, mut bytes: &[u8]) {
        while !self.dropped && !bytes.is_empty() {
            let take = (LOG_CHUNK - self.buf.len()).min(bytes.len());
            // `take <= remaining capacity`, so this cannot fail.
            let _ = self.buf.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buf.len() == LOG_CHUNK {
                self.send_current();
            }
        }
    }

    fn send_current(&mut self) {
        if LOG_OUTBOUND.try_send(mem::take(&mut self.buf)).is_err() {
            self.dropped = true;
        }
    }

    fn finish(mut self) {
        self.push_bytes(b"\r\n");
        if !self.dropped && !self.buf.is_empty() {
            let _ = LOG_OUTBOUND.try_send(self.buf);
        }
    }
}

impl Write for ChunkWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_bytes(s.as_bytes());
        Ok(())
    }
}

/// Collects an event's `message` field (and appends any structured fields) into the
/// chunked writer.
struct MessageVisitor<'a>(&'a mut ChunkWriter);

impl Visit for MessageVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }
}
