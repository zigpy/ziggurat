//! Python bindings embedding the Ziggurat Zigbee stack in-process.
//!
//! The host process (zigpy-ziggurat) owns the serial port. It shuttles raw bytes across
//! the FFI boundary — [`Ziggurat::feed`] for bytes read from the radio,
//! [`Ziggurat::read_outbound`] for bytes the stack wants written — while the control
//! plane stays the same JSON protocol the WebSocket server speaks, exchanged through
//! [`Ziggurat::send_message`] / [`Ziggurat::recv_message`]. Internally the Spinel client
//! runs over an in-memory duplex whose far end is the byte shuttle, and a session task
//! drives [`Api`] exactly as the server's connection handler does.
//!
//! Each instance owns its own tokio runtime, so there is no process-global runtime: the
//! task graph is scoped to the instance and reclaimed wholesale when it is closed or
//! dropped (`shutdown_background` drops the task futures, which breaks the stack's
//! self-referential `Arc` cycle that an abort-free drop would otherwise leak).

use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};

use pyo3::IntoPyObjectExt;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::runtime::{Builder, Handle, Runtime};
use tokio::sync::{Mutex as AsyncMutex, broadcast, mpsc};
use tokio::task::AbortHandle;

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

/// Worker threads per instance. Zigbee traffic is light, so a small pool keeps the thread
/// footprint bounded while still avoiding the single-thread starvation a current-thread
/// runtime could hit during a burst of crypto work.
const WORKER_THREADS: usize = 2;

/// Resolves a pending [`asyncio.Future`] from a runtime thread, guarded so a cancellation
/// that already completed the future is a no-op instead of an `InvalidStateError`. Cached
/// per interpreter; built once on first use.
static COMPLETE: OnceLock<Py<PyAny>> = OnceLock::new();

fn complete_fn<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    if let Some(complete) = COMPLETE.get() {
        return Ok(complete.bind(py).clone());
    }

    let code = c"
def complete(fut, is_exception, value):
    if fut.cancelled():
        return
    if is_exception:
        fut.set_exception(value)
    else:
        fut.set_result(value)
";
    let module = PyModule::from_code(py, code, c"_ziggurat_bridge.py", c"_ziggurat_bridge")?;
    let complete = module.getattr("complete")?.unbind();

    // A lost init race just drops the duplicate; the winner is equivalent.
    let _ = COMPLETE.set(complete);
    Ok(COMPLETE.get().unwrap().bind(py).clone())
}

/// A future done-callback that aborts the backing runtime task if the asyncio future was
/// cancelled, so a cancelled `recv_message` cannot leave a task that steals the next
/// message off the channel. A normal completion makes the abort a no-op.
#[pyclass]
struct Canceller {
    abort: Mutex<Option<AbortHandle>>,
}

#[pymethods]
impl Canceller {
    fn __call__(&self, future: &Bound<'_, PyAny>) -> PyResult<()> {
        if future.call_method0("cancelled")?.extract::<bool>()?
            && let Ok(mut abort) = self.abort.lock()
            && let Some(abort) = abort.take()
        {
            abort.abort();
        }
        Ok(())
    }
}

/// Bridge a Rust future onto the running asyncio loop: create a loop-owned future now,
/// drive the Rust future on `handle`, and complete the asyncio future from the runtime
/// thread via `call_soon_threadsafe`. Cancelling the asyncio future aborts the backing
/// task; shutting the runtime down drops it. Either way the asyncio future stops
/// resolving, which is what the caller wants when tearing down.
fn future_into_py<'py, F, T>(
    py: Python<'py>,
    handle: &Handle,
    future: F,
) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: for<'a> IntoPyObject<'a> + Send + 'static,
{
    let event_loop = py.import("asyncio")?.call_method0("get_running_loop")?;
    let py_fut = event_loop.call_method0("create_future")?;

    let loop_handle: Py<PyAny> = event_loop.clone().unbind();
    let fut_handle: Py<PyAny> = py_fut.clone().unbind();

    let task = handle.spawn(async move {
        let result = future.await;

        Python::attach(|py| {
            let event_loop = loop_handle.bind(py);
            let py_fut = fut_handle.bind(py);
            let Ok(complete) = complete_fn(py) else {
                return;
            };

            // A closed loop makes call_soon_threadsafe raise; nothing to do then.
            let _ = match result {
                Ok(value) => match value.into_bound_py_any(py) {
                    Ok(obj) => event_loop
                        .call_method1("call_soon_threadsafe", (&complete, py_fut, false, obj)),
                    Err(e) => event_loop.call_method1(
                        "call_soon_threadsafe",
                        (&complete, py_fut, true, e.into_value(py)),
                    ),
                },
                Err(err) => event_loop.call_method1(
                    "call_soon_threadsafe",
                    (&complete, py_fut, true, err.into_value(py)),
                ),
            };
        });
    });

    let canceller = Bound::new(
        py,
        Canceller {
            abort: Mutex::new(Some(task.abort_handle())),
        },
    )?;
    py_fut.call_method1("add_done_callback", (canceller,))?;

    Ok(py_fut)
}

/// An embedded Ziggurat stack, owning its tokio runtime.
#[pyclass]
struct Ziggurat {
    /// For spawning the bridge futures; valid until the runtime is shut down.
    handle: Handle,
    /// The owned runtime, taken on `close` (or drop) to reclaim the whole task graph.
    runtime: Mutex<Option<Runtime>>,
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
        let runtime = Builder::new_multi_thread()
            .worker_threads(WORKER_THREADS)
            .enable_all()
            .thread_name("ziggurat")
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        let handle = runtime.handle().clone();

        // `spawn_reader_graceful` calls `tokio::spawn`, which needs the runtime context
        // active on this thread for the duration of construction.
        let _guard = handle.enter();

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

        handle.spawn(run_session(api, inbound_rx, outbound_tx));

        let (serial_out, serial_in) = tokio::io::split(embedder_side);

        Ok(Self {
            handle,
            runtime: Mutex::new(Some(runtime)),
            inbound_tx,
            outbound_rx: Arc::new(AsyncMutex::new(outbound_rx)),
            serial_in: Arc::new(AsyncMutex::new(serial_in)),
            serial_out: Arc::new(AsyncMutex::new(serial_out)),
        })
    }

    /// Submit a JSON-RPC request string, the analogue of a WebSocket text send.
    fn send_message<'py>(&self, py: Python<'py>, message: String) -> PyResult<Bound<'py, PyAny>> {
        let inbound_tx = self.inbound_tx.clone();

        future_into_py(py, &self.handle, async move {
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

        future_into_py(py, &self.handle, async move {
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

        future_into_py(py, &self.handle, async move {
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

        future_into_py(py, &self.handle, async move {
            let mut serial_out = serial_out.lock().await;
            let mut buffer = [0u8; OUTBOUND_CHUNK];

            let n = serial_out
                .read(&mut buffer)
                .await
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

            Python::attach(|py| Ok(PyBytes::new(py, &buffer[..n]).unbind()))
        })
    }

    /// Stop the stack and reclaim every task. Idempotent; further calls are no-ops.
    fn close(&self) {
        self.shutdown();
    }
}

impl Ziggurat {
    /// Take and shut down the runtime without blocking. Dropping the runtime drops every
    /// task future, releasing the `Arc<ZigbeeStack>` clones they hold and tearing down
    /// the stack; the in-flight bridge futures simply never resolve.
    fn shutdown(&self) {
        if let Ok(mut runtime) = self.runtime.lock()
            && let Some(runtime) = runtime.take()
        {
            runtime.shutdown_background();
        }
    }
}

impl Drop for Ziggurat {
    fn drop(&mut self) {
        self.shutdown();
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
