//! Embedded dispatch for the binary control protocol: it routes parsed requests to
//! the live `ZigbeeStack` and streams the replies onto [`crate::OUTBOUND`].

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;

use ziggurat_driver::runtime::Spawn;
use ziggurat_driver::zigbee_stack::{Tunables, ZigbeeStack};
use ziggurat_phy::{RadioPhy, Receiver};
use ziggurat_protocol::{
    self as proto, CapturedPacketPayload, ChannelPayload, CommandId, ConfigurePayload,
    EnergyResultPayload, Error, Event, FirmwareInfoPayload, HwAddressPayload, NwkUpdateIdPayload,
    PermitJoinsPayload, ProvisionalKeyPayload, Request, RequestHeader, RequestId, ResetPayload,
    Response, ScanCountPayload, ScanRequestPayload, Status,
};

use crate::{App, CaptureStop, capture_config, push_outbound, send_outbound, spawn_stack_pumps};

// Re-exported for the transport shell (`crate::lib`) and downstream firmware.
pub use ziggurat_protocol::{
    HelloPayload, LastResetPayload, Notification, PROTOCOL_VERSION, notification_frame,
};

async fn send_event(request_id: RequestId, event: Event) {
    if let Some(frame) = event.frame(request_id) {
        send_outbound(frame).await;
    }
}

// -- dispatch ------------------------------------------------------------------------

/// Dispatch one inbound frame; every path emits exactly one response or error,
/// preceded by any streamed events.
pub async fn handle_frame<P: RadioPhy>(app: &mut App<P>, bytes: &[u8]) {
    let Some((header, consumed)) = RequestHeader::parse(bytes) else {
        send_outbound(Error::parse("truncated header").frame(0, 0)).await;
        return;
    };
    let payload = &bytes[consumed..];
    let request_id = header.request_id;

    let request = CommandId::try_from(header.command)
        .map_err(|_| Error::new(Status::UnknownCommand, ""))
        .and_then(|command| Request::parse(command, payload));

    let reply = match request {
        Ok(request) => dispatch(app, request_id, request).await,
        Err(e) => Err(e),
    };

    let frame = match reply {
        Ok(response) => response.frame(header.command, request_id),
        Err(e) => e.frame(header.command, request_id),
    };
    send_outbound(frame).await;
}

async fn dispatch<P: RadioPhy>(
    app: &mut App<P>,
    request_id: RequestId,
    request: Request,
) -> Result<Response, Error> {
    match request {
        Request::Ping => Ok(Response::Empty),
        Request::Reset(payload) => handle_reset(app, payload),
        Request::GetFirmwareInfo => {
            let version = concat!("ziggurat/", env!("CARGO_PKG_VERSION"));
            Ok(Response::FirmwareInfo(FirmwareInfoPayload {
                protocol_version: PROTOCOL_VERSION,
                version: version.as_bytes().to_vec(),
            }))
        }
        Request::GetHwAddress => Ok(Response::HwAddress(HwAddressPayload {
            ieee: app.platform.hw_eui64(),
        })),
        Request::Shutdown => handle_shutdown(app).await,
        Request::Configure(payload) => handle_configure(app, payload).await,
        Request::LoadKeyTable(payload) => {
            proto::apply_key_table(&**loadable(app)?, payload);
            Ok(Response::Empty)
        }
        Request::LoadChildren(payload) => {
            proto::apply_children(&**loadable(app)?, payload);
            Ok(Response::Empty)
        }
        Request::LoadAddressCache(payload) => {
            proto::apply_address_cache(&**loadable(app)?, payload);
            Ok(Response::Empty)
        }
        Request::StartNetwork => handle_start_network(app).await,
        Request::GetNetworkInfo => Ok(Response::NetworkInfo(proto::network_info_payload(
            &**configured(app)?,
            app.started,
        ))),
        Request::ScanKeyTable => {
            scan_table(app, request_id, |stack| {
                proto::key_entries(stack)
                    .into_iter()
                    .map(Event::KeyEntry)
                    .collect()
            })
            .await
        }
        Request::ScanChildren => {
            scan_table(app, request_id, |stack| {
                proto::child_entries(stack)
                    .into_iter()
                    .map(Event::Child)
                    .collect()
            })
            .await
        }
        Request::ScanAddressCache => {
            scan_table(app, request_id, |stack| {
                proto::address_entries(stack)
                    .into_iter()
                    .map(Event::Address)
                    .collect()
            })
            .await
        }
        Request::ScanRouteTable => {
            scan_table(app, request_id, |stack| {
                proto::route_entries(stack)
                    .into_iter()
                    .map(Event::Route)
                    .collect()
            })
            .await
        }
        Request::SendAps(payload) => {
            proto::send_aps(&**running(app)?, payload, request_id)?;
            Ok(Response::Empty)
        }
        Request::PermitJoins(payload) => handle_permit_joins(app, payload),
        Request::SetChannel(payload) => handle_set_channel(app, payload).await,
        Request::SetNwkUpdateId(payload) => handle_set_nwk_update_id(app, payload),
        Request::SetProvisionalKey(payload) => handle_set_provisional_key(app, payload),
        Request::EnergyScan(payload) => handle_energy_scan(app, request_id, payload).await,
        Request::NetworkScan(payload) => handle_network_scan(app, request_id, payload).await,
        Request::PacketCapture(payload) => handle_packet_capture(app, request_id, payload).await,
        Request::PacketCaptureChannel(payload) => {
            handle_packet_capture_channel(app, payload).await
        }
    }
}

// -- guards ------------------------------------------------------------------------

/// The stack, in any state after `configure`.
fn configured<P: RadioPhy>(app: &App<P>) -> Result<&Arc<ZigbeeStack<P>>, Error> {
    app.stack.as_ref().ok_or_else(Error::not_configured)
}

/// The stack, if it is in the load window (configured but not started).
fn loadable<P: RadioPhy>(app: &App<P>) -> Result<&Arc<ZigbeeStack<P>>, Error> {
    match app.stack.as_ref() {
        Some(stack) if !app.started => Ok(stack),
        Some(_) => Err(Error::new(Status::InvalidState, "network already started")),
        None => Err(Error::not_configured()),
    }
}

/// The stack, if it is running.
fn running<P: RadioPhy>(app: &App<P>) -> Result<&Arc<ZigbeeStack<P>>, Error> {
    match app.stack.as_ref() {
        Some(stack) if app.started => Ok(stack),
        _ => Err(Error::not_configured()),
    }
}

// -- handlers ----------------------------------------------------------------------

/// Soft reset stops transient radio activity; hard reset reboots (diverges).
fn handle_reset<P: RadioPhy>(app: &mut App<P>, request: ResetPayload) -> Result<Response, Error> {
    if let Some(stop) = app.capture_stop.take() {
        stop.signal(());
    }

    if request.hard {
        app.platform.hard_reset();
    }

    Ok(Response::Empty)
}

/// Tear the stack fully down.
async fn handle_shutdown<P: RadioPhy>(app: &mut App<P>) -> Result<Response, Error> {
    if let Some(stop) = app.capture_stop.take() {
        stop.signal(());
    }

    if let Some(stack) = app.stack.take() {
        stack.shutdown().await;
    }
    app.started = false;

    // Clear the source-match table
    if let Err(e) = app.phy.set_frame_pending_table(&[], &[]).await {
        return Err(Error::new(Status::RadioError, &e.to_string()));
    }

    Ok(Response::Empty)
}

async fn handle_configure<P: RadioPhy>(
    app: &mut App<P>,
    request: ConfigurePayload,
) -> Result<Response, Error> {
    let config = proto::network_config(&request);

    if let Some(old_stack) = app.stack.take() {
        old_stack.shutdown().await;
    }
    app.started = false;

    let stack = ZigbeeStack::new(app.phy.clone(), config, Tunables::new(), app.spawner);
    stack
        .state
        .core
        .lock()
        .aib
        .aps_security
        .restore_outgoing_frame_counter(request.state.aps_frame_counter);
    app.stack = Some(stack);

    Ok(Response::Empty)
}

async fn handle_start_network<P: RadioPhy>(app: &mut App<P>) -> Result<Response, Error> {
    let stack = loadable(app)?.clone();

    if let Err(e) = stack.start_network().await {
        return Err(Error::new(Status::NetworkStartFailed, &e.to_string()));
    }

    spawn_stack_pumps(&stack);
    app.started = true;
    Ok(Response::Empty)
}

/// Stream one table scan: snapshot under the core lock, then stream outside it
/// (the awaiting sends must not hold the mutex), then respond with the count.
async fn scan_table<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    snapshot: impl FnOnce(&ZigbeeStack<P>) -> Vec<Event>,
) -> Result<Response, Error> {
    let stack = configured(app)?;

    let events = snapshot(stack);
    let count = events.len() as u16;
    for event in events {
        send_event(request_id, event).await;
    }

    Ok(Response::ScanCount(ScanCountPayload { count }))
}

fn handle_permit_joins<P: RadioPhy>(
    app: &App<P>,
    request: PermitJoinsPayload,
) -> Result<Response, Error> {
    let stack = running(app)?;

    stack.permit_joins(u64::from(request.duration), request.accept_direct_joins);
    Ok(Response::Empty)
}

async fn handle_set_channel<P: RadioPhy>(
    app: &App<P>,
    request: ChannelPayload,
) -> Result<Response, Error> {
    let stack = running(app)?.clone();

    match stack.set_channel(request.channel).await {
        Ok(()) => Ok(Response::Empty),
        Err(e) => Err(Error::new(Status::RadioError, &e.to_string())),
    }
}

fn handle_set_nwk_update_id<P: RadioPhy>(
    app: &App<P>,
    request: NwkUpdateIdPayload,
) -> Result<Response, Error> {
    let stack = running(app)?;

    stack.set_nwk_update_id(request.nwk_update_id);
    Ok(Response::Empty)
}

fn handle_set_provisional_key<P: RadioPhy>(
    app: &App<P>,
    request: ProvisionalKeyPayload,
) -> Result<Response, Error> {
    let stack = running(app)?;

    stack.set_provisional_key(request.ieee, request.key);
    Ok(Response::Empty)
}

async fn handle_energy_scan<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    request: ScanRequestPayload,
) -> Result<Response, Error> {
    let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
    for channel in request.channels {
        match app.phy.energy_detect(channel, duration).await {
            Ok(rssi) => {
                send_event(
                    request_id,
                    Event::EnergyResult(EnergyResultPayload {
                        channel,
                        rssi: rssi as u8,
                    }),
                )
                .await;
            }
            Err(e) => return Err(Error::new(Status::ScanFailed, &e.to_string())),
        }
    }

    Ok(Response::Empty)
}

async fn handle_network_scan<P: RadioPhy>(
    app: &App<P>,
    request_id: RequestId,
    request: ScanRequestPayload,
) -> Result<Response, Error> {
    let stack = running(app)?.clone();

    stack.begin_network_scan();
    let duration = Duration::from_millis(u64::from(request.duration_per_channel_ms));
    let result = stack.run_network_scan(&request.channels, duration).await;

    loop {
        let batch = stack.next_scan_beacons().await;
        if batch.is_empty() {
            break;
        }
        for beacon in batch {
            send_event(request_id, Event::Beacon((&beacon).into())).await;
        }
    }

    match result {
        Ok(()) => Ok(Response::Empty),
        Err(e) => Err(Error::new(Status::ScanFailed, &e.to_string())),
    }
}

async fn handle_packet_capture<P: RadioPhy>(
    app: &mut App<P>,
    request_id: RequestId,
    request: ChannelPayload,
) -> Result<Response, Error> {
    if let Err(e) = app.phy.reconfigure(&capture_config(request.channel)).await {
        return Err(Error::new(Status::RadioError, &e.to_string()));
    }

    // Already capturing: the reconfigure above retuned it; don't spawn a second task.
    if app.capture_stop.is_none() {
        let stop = Arc::new(CaptureStop::new());
        app.capture_stop = Some(stop.clone());

        let phy = app.phy.clone();
        app.spawner.spawn(alloc::boxed::Box::pin(async move {
            let mut rx = phy.subscribe_rx();
            loop {
                match embassy_futures::select::select(rx.recv(), stop.wait()).await {
                    embassy_futures::select::Either::First(Some(frame)) => {
                        let event = Event::CapturedPacket(CapturedPacketPayload {
                            channel: frame.channel,
                            rssi: frame.rssi as u8,
                            lqi: frame.lqi,
                            psdu: frame.psdu,
                        });
                        // Drop on a full queue: a sniffer must not block.
                        if let Some(bytes) = event.frame(request_id) {
                            push_outbound(bytes);
                        }
                    }
                    _ => break,
                }
            }
        }));
    }

    Ok(Response::Empty)
}

async fn handle_packet_capture_channel<P: RadioPhy>(
    app: &App<P>,
    request: ChannelPayload,
) -> Result<Response, Error> {
    match app.phy.reconfigure(&capture_config(request.channel)).await {
        Ok(()) => Ok(Response::Empty),
        Err(e) => Err(Error::new(Status::RadioError, &e.to_string())),
    }
}
