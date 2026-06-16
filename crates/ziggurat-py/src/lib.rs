//! Python bindings embedding the Ziggurat Zigbee stack in-process.
//!
//! The host process (zigpy-ziggurat) owns the serial port. It shuttles raw bytes across
//! the FFI boundary — [`Ziggurat::feed`] for bytes read from the radio,
//! [`Ziggurat::read_outbound`] for bytes the stack wants written — while the control
//! plane stays the same JSON protocol the WebSocket server speaks, exchanged through
//! [`Ziggurat::send_message`] / [`Ziggurat::recv_message`]. Internally the Spinel client
//! runs over an in-memory duplex whose far end is the byte shuttle, and a session task
//! drives [`Api`] exactly as the server's connection handler does.

use std::sync::Arc;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{Mutex as AsyncMutex, broadcast, mpsc};

use spinel::client::SpinelClient;
use ziggurat_api::{Api, error_response, event, hello, notification_to_message};

/// Capacity of the in-memory pipe between the Spinel client and the byte shuttle. Spinel
/// frames are a couple of KiB at most; this leaves ample slack so a write never blocks
/// waiting on the reader.
const DUPLEX_BUF: usize = 64 * 1024;

/// Control-plane messages buffered toward the Python client before backpressure. Mirrors
/// the WebSocket server's outbound queue depth.
const OUTBOUND_QUEUE_DEPTH: usize = 1024;

/// The maximum chunk handed to Python per `read_outbound` call.
const OUTBOUND_CHUNK: usize = 2048;

/// An embedded Ziggurat stack. Construction starts the runtime tasks; dropping the
/// object closes the byte shuttle, which stops the Spinel reader and ends the session.
#[pyclass]
struct Ziggurat {
    /// Carries request JSON strings from Python into the session task.
    inbound_tx: mpsc::Sender<String>,
    /// Carries response/event/notification JSON values from the session task to Python.
    outbound_rx: Arc<AsyncMutex<mpsc::Receiver<Value>>>,
    /// Bytes received from the radio are written here; the Spinel client reads them.
    serial_in: Arc<AsyncMutex<WriteHalf<DuplexStream>>>,
    /// Bytes the Spinel client wants on the wire surface here, to be sent to the radio.
    serial_out: Arc<AsyncMutex<ReadHalf<DuplexStream>>>,
}

#[pymethods]
impl Ziggurat {
    #[new]
    fn new() -> PyResult<Self> {
        let rt = pyo3_async_runtimes::tokio::get_runtime();
        // The reader and session tasks below call `tokio::spawn`, which needs the runtime
        // context active for the duration of construction.
        let _guard = rt.enter();

        // One end of the pipe is the Spinel client's transport; the other is the byte
        // shuttle. Writing to `serial_in` is readable by the client (radio -> stack);
        // reading `serial_out` drains what the client wrote (stack -> radio).
        let (client_side, embedder_side) = tokio::io::duplex(DUPLEX_BUF);
        let spinel = Arc::new(SpinelClient::new(client_side));
        // The transport closing is a normal shutdown here, not a fault: never kill the
        // host process the way the standalone server does.
        spinel.spawn_reader_graceful();

        // The client already exists, so the factory is infallible and never reopens.
        let api = Api::new(Box::new(move || Ok(spinel.clone())));

        let (inbound_tx, inbound_rx) = mpsc::channel::<String>(64);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Value>(OUTBOUND_QUEUE_DEPTH);

        rt.spawn(run_session(api, inbound_rx, outbound_tx));

        let (serial_out, serial_in) = tokio::io::split(embedder_side);

        Ok(Self {
            inbound_tx,
            outbound_rx: Arc::new(AsyncMutex::new(outbound_rx)),
            serial_in: Arc::new(AsyncMutex::new(serial_in)),
            serial_out: Arc::new(AsyncMutex::new(serial_out)),
        })
    }

    /// Submit a JSON-RPC request string, the analogue of a WebSocket text send.
    fn send_message<'py>(&self, py: Python<'py>, message: String) -> PyResult<Bound<'py, PyAny>> {
        let inbound_tx = self.inbound_tx.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            inbound_tx
                .send(message)
                .await
                .map_err(|_| PyRuntimeError::new_err("ziggurat stack stopped"))?;
            Ok(())
        })
    }

    /// Await the next outbound control-plane message (response, event, or notification)
    /// as a JSON string, the analogue of a WebSocket text receive.
    fn recv_message<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let outbound_rx = self.outbound_rx.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut outbound_rx = outbound_rx.lock().await;

            outbound_rx
                .recv()
                .await
                .map(|value| value.to_string())
                .ok_or_else(|| PyRuntimeError::new_err("ziggurat stack stopped"))
        })
    }

    /// Hand the stack bytes read from the radio.
    fn feed<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let serial_in = self.serial_in.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut serial_in = serial_in.lock().await;

            serial_in
                .write_all(&data)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            Ok(())
        })
    }

    /// Await the next chunk of bytes the stack wants written to the radio. An empty
    /// result means the stack has shut down its side of the pipe.
    fn read_outbound<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let serial_out = self.serial_out.clone();

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut serial_out = serial_out.lock().await;
            let mut buffer = [0u8; OUTBOUND_CHUNK];

            let n = serial_out
                .read(&mut buffer)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

            Python::attach(|py| Ok(PyBytes::new(py, &buffer[..n]).unbind()))
        })
    }
}

/// Drives [`Api`] over the in-process channels, mirroring the WebSocket server's
/// per-connection handler: greet, forward notifications, then dispatch each request on
/// its own task so a slow command never blocks the others.
async fn run_session(
    api: Arc<Api>,
    mut inbound: mpsc::Receiver<String>,
    outbound: mpsc::Sender<Value>,
) {
    let _ = outbound.send(hello(api.is_configured())).await;

    let mut notifications = api.subscribe();
    let notification_outbound = outbound.clone();
    tokio::spawn(async move {
        loop {
            match notifications.recv().await {
                Ok(event) => {
                    if notification_outbound
                        .send(notification_to_message(event))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    tracing::warn!("Python client lagged {count} notifications");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    while let Some(text) = inbound.recv().await {
        let request: Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(e) => {
                let _ = outbound.send(error_response(0, "invalid_request", e)).await;
                continue;
            }
        };

        let (Some(id), Some(method)) = (request["id"].as_u64(), request["method"].as_str()) else {
            let _ = outbound
                .send(error_response(0, "invalid_request", "missing id or method"))
                .await;
            continue;
        };
        let method = method.to_owned();
        let params = request.get("params").cloned().unwrap_or(Value::Null);

        let _ = outbound.send(event(id, "accepted")).await;

        let api = api.clone();
        let outbound = outbound.clone();
        tokio::spawn(async move {
            let message = api.dispatch(id, &method, params, &outbound).await;
            let _ = outbound.send(message).await;
        });
    }
}

#[pymodule]
fn ziggurat_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Route the stack's `tracing` events into Python's `logging`. The `log-always`
    // feature on `tracing` turns every event into a `log` record, which pyo3-log
    // forwards. Ignore a double-init if the module is imported more than once.
    let _ = pyo3_log::try_init();

    m.add_class::<Ziggurat>()?;
    Ok(())
}
