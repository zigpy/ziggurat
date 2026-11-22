//! The local application endpoints and the ZCL reception rules (ZCL 2.3.2): which
//! endpoints a frame reaches, which commands they carry out, and when a Default
//! Response goes back.

use alloc::boxed::Box;
use alloc::vec::Vec;
use ziggurat_ieee_802154::types::Nwk;
use ziggurat_ieee_802154::{FrameWriter, write_frame};

use super::cluster::{self, ClusterServer, CommandOutcome};
use super::foundation::{
    DefaultResponse, DiscoverAttributes, GlobalCommandId, ReadAttributes, Status, WriteAttributes,
};
use super::frame::{Direction, FrameType, ZclHeader};
use crate::Instant;
use crate::aps::frame::{Asdu, MAX_ASDU_SIZE};
use crate::crypto::MIC_LENGTH;
use crate::zdp::SimpleDescriptor;

/// ZCL 2.3.2.1: a frame to this endpoint reaches every endpoint with the cluster.
pub const BROADCAST_ENDPOINT: u8 = 0xFF;

/// The ASDU room every frame loses to NWK security: the auxiliary header (frame
/// control, frame counter, source address, key sequence number) and the MIC.
const NWK_SECURITY_OVERHEAD: usize = 14 + MIC_LENGTH;

/// The ASDU room a response mirroring APS security also loses: the auxiliary header
/// with an extended nonce, and the MIC.
const APS_SECURITY_OVERHEAD: usize = 13 + MIC_LENGTH;

/// One application endpoint the stack serves, with the server side of its clusters.
/// Its client clusters only appear in its simple descriptor.
#[derive(Debug)]
pub struct Endpoint {
    pub endpoint: u8,
    pub profile_id: u16,
    pub device_id: u16,
    pub device_version: u8,
    pub servers: Vec<Box<dyn ClusterServer>>,
    pub client_clusters: Vec<u16>,
}

impl Endpoint {
    /// The descriptor ZDP requests read, derived from the clusters actually served.
    pub fn simple_descriptor(&self) -> SimpleDescriptor {
        SimpleDescriptor {
            endpoint: self.endpoint,
            profile_id: self.profile_id,
            device_id: self.device_id,
            device_version: self.device_version,
            input_clusters: self
                .servers
                .iter()
                .map(|server| server.cluster_id())
                .collect(),
            output_clusters: self.client_clusters.clone(),
        }
    }

    fn server(&mut self, cluster_id: u16) -> Option<&mut Box<dyn ClusterServer>> {
        self.servers
            .iter_mut()
            .find(|server| server.cluster_id() == cluster_id)
    }

    fn has_cluster(&self, cluster_id: u16) -> bool {
        self.servers
            .iter()
            .any(|server| server.cluster_id() == cluster_id)
            || self.client_clusters.contains(&cluster_id)
    }
}

/// A ZCL frame the APS layer delivered to an endpoint (not a group).
#[derive(Debug, Clone)]
pub struct Indication<'a> {
    pub source: Nwk,
    pub source_endpoint: u8,
    pub destination_endpoint: u8,
    pub profile_id: u16,
    pub cluster_id: u16,
    /// Sent to one device as an APS unicast, rather than broadcast.
    pub unicast: bool,
    /// Secured with an APS link key, which the response mirrors.
    pub aps_secured: bool,
    pub asdu: &'a [u8],
}

/// A ZCL frame to send back to the originator of an indication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub destination: Nwk,
    pub source_endpoint: u8,
    pub destination_endpoint: u8,
    pub profile_id: u16,
    pub cluster_id: u16,
    pub asdu: Asdu,
}

/// What a received command led to, before the Default Response rules apply.
enum Outcome {
    /// A response command of its own.
    Respond {
        frame_type: FrameType,
        command_id: u8,
        payload: Asdu,
    },
    /// No response command: a Default Response may report the status.
    Status(Status),
    /// Nothing goes back, not even a Default Response.
    Silent,
}

/// The stack's application endpoints.
#[derive(Debug, Default)]
pub struct Endpoints {
    /// Sorted by endpoint.
    endpoints: Vec<Endpoint>,
}

impl Endpoints {
    /// Add an endpoint. Endpoints are set up once, so adding one twice is a bug.
    pub fn add(&mut self, endpoint: Endpoint) {
        assert!(
            (1..=240).contains(&endpoint.endpoint),
            "endpoint {} is not an application endpoint",
            endpoint.endpoint
        );

        match self
            .endpoints
            .binary_search_by_key(&endpoint.endpoint, |existing| existing.endpoint)
        {
            Ok(_) => panic!("endpoint {} is already served", endpoint.endpoint),
            Err(index) => self.endpoints.insert(index, endpoint),
        }
    }

    pub fn contains(&self, endpoint: u8) -> bool {
        self.endpoints
            .iter()
            .any(|existing| existing.endpoint == endpoint)
    }

    /// ZCL 2.3.2: carry out a received frame on the endpoints it reaches and return
    /// what goes back. A frame for an endpoint we do not serve is not ours.
    pub fn receive(&mut self, indication: &Indication, now: Instant) -> Vec<Reply> {
        // A header we cannot parse has no transaction to answer
        let Ok((header, payload)) = ZclHeader::parse(indication.asdu) else {
            return Vec::new();
        };

        // ZCL 2.3.2.1: the broadcast endpoint reaches only the endpoints with the
        // cluster, and never draws error responses
        let broadcast_endpoint = indication.destination_endpoint == BROADCAST_ENDPOINT;
        let unicast = indication.unicast && !broadcast_endpoint;

        let room = MAX_ASDU_SIZE
            - NWK_SECURITY_OVERHEAD
            - if indication.aps_secured {
                APS_SECURITY_OVERHEAD
            } else {
                0
            };

        self.endpoints
            .iter_mut()
            .filter(|endpoint| {
                if broadcast_endpoint {
                    endpoint.has_cluster(indication.cluster_id)
                } else {
                    endpoint.endpoint == indication.destination_endpoint
                }
            })
            .filter_map(|endpoint| {
                let outcome = carry_out(endpoint, indication, &header, payload, room, now);
                let (frame_type, command_id, payload) = reply_command(outcome, &header, unicast)?;

                let response = header.response(frame_type, command_id);
                let asdu = write_frame::<MAX_ASDU_SIZE>(|writer| {
                    response.serialize(writer)?;
                    writer.extend(&payload)
                })
                .expect("the response was built to fit");

                Some(Reply {
                    destination: indication.source,
                    source_endpoint: endpoint.endpoint,
                    destination_endpoint: indication.source_endpoint,
                    profile_id: indication.profile_id,
                    cluster_id: indication.cluster_id,
                    asdu,
                })
            })
            .collect()
    }
}

/// ZCL 2.5.12.2: the response command to send, if any. A command's own response goes
/// back however it arrived. A Default Response goes back only for a unicast command,
/// when no other response does, and only when the sender asked for one or the command
/// failed.
fn reply_command(
    outcome: Outcome,
    header: &ZclHeader,
    unicast: bool,
) -> Option<(FrameType, u8, Asdu)> {
    match outcome {
        Outcome::Silent => None,
        // A command sent to many devices draws no Default Response, even in error
        Outcome::Status(_) if !unicast => None,
        Outcome::Respond {
            frame_type,
            command_id,
            payload,
        } => Some((frame_type, command_id, payload)),
        Outcome::Status(Status::Success) if header.disable_default_response => None,
        Outcome::Status(status) => {
            let payload = write_frame(|writer| {
                writer.bits(&DefaultResponse {
                    command_id: header.command_id,
                    status,
                })
            })
            .expect("a Default Response fits");
            Some((
                FrameType::Global,
                GlobalCommandId::DefaultResponse as u8,
                payload,
            ))
        }
    }
}

/// Carry out one command on one endpoint.
fn carry_out(
    endpoint: &mut Endpoint,
    indication: &Indication,
    header: &ZclHeader,
    payload: &[u8],
    room: usize,
    now: Instant,
) -> Outcome {
    // A Default Response is never answered, whatever it carries (ZCL 2.5.12.2)
    if header.frame_type == FrameType::Global
        && header.command_id == GlobalCommandId::DefaultResponse as u8
    {
        return Outcome::Silent;
    }

    // ZCL 2.5.12.2: a cluster the endpoint lacks
    if !endpoint.has_cluster(indication.cluster_id) {
        return Outcome::Status(Status::UnsupportedCluster);
    }

    // We implement no manufacturer specific commands, and serve no client side
    if header.manufacturer_code.is_some() || header.direction == Direction::ServerToClient {
        return Outcome::Status(Status::UnsupCommand);
    }

    let Some(server) = endpoint.server(indication.cluster_id) else {
        return Outcome::Status(Status::UnsupCommand);
    };

    // The room left for the payload once the response header is in
    let room = room
        - if header.manufacturer_code.is_some() {
            5
        } else {
            3
        };

    match header.frame_type {
        FrameType::Global => carry_out_global(&mut **server, header.command_id, payload, room, now),
        FrameType::ClusterSpecific => match server.command(header.command_id, payload, now) {
            CommandOutcome::Done => Outcome::Status(Status::Success),
            CommandOutcome::Failed(status) => Outcome::Status(status),
            CommandOutcome::Respond {
                command_id,
                payload,
            } => match Asdu::from_slice(&payload) {
                Ok(payload) if payload.len() <= room => Outcome::Respond {
                    frame_type: FrameType::ClusterSpecific,
                    command_id,
                    payload,
                },
                _ => Outcome::Status(Status::InsufficientSpace),
            },
        },
    }
}

fn carry_out_global(
    server: &mut dyn ClusterServer,
    command_id: u8,
    payload: &[u8],
    room: usize,
    now: Instant,
) -> Outcome {
    let mut buffer = Asdu::new();
    let mut writer = FrameWriter::new(&mut buffer, room);

    let response = match GlobalCommandId::try_from(command_id) {
        Ok(GlobalCommandId::ReadAttributes) => {
            let request = ReadAttributes::parse(payload);
            cluster::read_attributes(server, &request, now, &mut writer);
            GlobalCommandId::ReadAttributesResponse
        }
        Ok(GlobalCommandId::WriteAttributes) => {
            let Ok(request) = WriteAttributes::parse(payload) else {
                return Outcome::Status(Status::MalformedCommand);
            };
            cluster::write_attributes(server, request, now)
                .serialize(&mut writer)
                .expect("a write response fits");
            GlobalCommandId::WriteAttributesResponse
        }
        Ok(GlobalCommandId::WriteAttributesUndivided) => {
            let Ok(request) = WriteAttributes::parse(payload) else {
                return Outcome::Status(Status::MalformedCommand);
            };
            cluster::write_attributes_undivided(server, request, now)
                .serialize(&mut writer)
                .expect("a write response fits");
            GlobalCommandId::WriteAttributesResponse
        }
        // ZCL 2.5.6.3: no response of any kind, even to a malformed command
        Ok(GlobalCommandId::WriteAttributesNoResponse) => {
            if let Ok(request) = WriteAttributes::parse(payload) {
                cluster::write_attributes_no_response(server, request, now);
            }
            return Outcome::Silent;
        }
        Ok(GlobalCommandId::DiscoverAttributes) => {
            let Ok(request) = DiscoverAttributes::parse(payload) else {
                return Outcome::Status(Status::MalformedCommand);
            };
            cluster::discover_attributes(server, &request, &writer)
                .serialize(&mut writer)
                .expect("the discovery was sized to fit");
            GlobalCommandId::DiscoverAttributesResponse
        }
        // Reporting, structured access, command discovery, and the responses to
        // commands we never send
        _ => return Outcome::Status(Status::UnsupCommand),
    };

    Outcome::Respond {
        frame_type: FrameType::Global,
        command_id: response as u8,
        payload: buffer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zcl::clusters::basic::{self, Basic, BasicInfo, PowerSource};
    use alloc::vec;

    const ON_OFF_CLUSTER_ID: u16 = 0x0006;

    fn endpoint(endpoint: u8, client_clusters: Vec<u16>) -> Endpoint {
        Endpoint {
            endpoint,
            profile_id: 0x0104,
            device_id: 0x0008,
            device_version: 0,
            servers: vec![Box::new(Basic::new(&BasicInfo {
                power_source: PowerSource::MainsSinglePhase,
                battery_backup: false,
                manufacturer_name: None,
                model_identifier: None,
                date_code: None,
                sw_build_id: None,
            }))],
            client_clusters,
        }
    }

    fn receive(
        endpoints: &mut Endpoints,
        destination_endpoint: u8,
        cluster_id: u16,
        unicast: bool,
        asdu: &[u8],
    ) -> Vec<(u8, Vec<u8>)> {
        let indication = Indication {
            source: Nwk(0x0000),
            source_endpoint: 1,
            destination_endpoint,
            profile_id: 0x0104,
            cluster_id,
            unicast,
            aps_secured: false,
            asdu,
        };

        endpoints
            .receive(&indication, Instant::from_micros(0))
            .into_iter()
            .map(|reply| (reply.source_endpoint, reply.asdu.to_vec()))
            .collect()
    }

    #[test]
    fn default_response_only_for_unicast_and_never_beside_another_response() {
        let mut endpoints = Endpoints::default();
        endpoints.add(endpoint(1, vec![]));

        // A cluster the endpoint lacks: UNSUPPORTED_CLUSTER, server to client, no
        // Default Response asked for in return
        let read_on_off = [0x00, 0x10, 0x00, 0x00, 0x00];
        assert_eq!(
            receive(&mut endpoints, 1, ON_OFF_CLUSTER_ID, true, &read_on_off),
            [(1, vec![0x18, 0x10, 0x0B, 0x00, 0xC3])]
        );
        // The same, broadcast: discarded silently
        assert_eq!(
            receive(&mut endpoints, 1, ON_OFF_CLUSTER_ID, false, &read_on_off),
            []
        );

        // A cluster-specific command Basic does not implement fails even when no
        // Default Response was asked for
        assert_eq!(
            receive(
                &mut endpoints,
                1,
                basic::CLUSTER_ID,
                true,
                &[0x11, 0x20, 0x00]
            ),
            [(1, vec![0x18, 0x20, 0x0B, 0x00, 0x81])]
        );

        // A Read Attributes Response is the only response, even with the Default
        // Response asked for. ZCLVersion reads 8
        assert_eq!(
            receive(
                &mut endpoints,
                1,
                basic::CLUSTER_ID,
                true,
                &[0x00, 0x30, 0x00, 0x00, 0x00]
            ),
            [(1, vec![0x18, 0x30, 0x01, 0x00, 0x00, 0x00, 0x20, 0x08])]
        );

        // A Default Response is never answered
        assert_eq!(
            receive(
                &mut endpoints,
                1,
                basic::CLUSTER_ID,
                true,
                &[0x00, 0x40, 0x0B, 0x00, 0x81]
            ),
            []
        );
    }

    #[test]
    fn broadcast_endpoint_reaches_only_endpoints_with_the_cluster() {
        let mut endpoints = Endpoints::default();
        endpoints.add(endpoint(1, vec![]));
        endpoints.add(endpoint(2, vec![ON_OFF_CLUSTER_ID]));

        // Both serve Basic: both answer a read, though it is not unicast
        let read_basic = [0x10, 0x50, 0x00, 0x00, 0x00];
        let replies = receive(
            &mut endpoints,
            BROADCAST_ENDPOINT,
            basic::CLUSTER_ID,
            true,
            &read_basic,
        );
        assert_eq!(
            replies
                .iter()
                .map(|(endpoint, _)| *endpoint)
                .collect::<Vec<_>>(),
            [1, 2]
        );

        // Only endpoint 2 has On/Off, as a client: the command is not for its client
        // side, but through the broadcast endpoint the error goes unanswered
        let read_on_off = [0x00, 0x60, 0x00, 0x00, 0x00];
        assert_eq!(
            receive(
                &mut endpoints,
                BROADCAST_ENDPOINT,
                ON_OFF_CLUSTER_ID,
                true,
                &read_on_off
            ),
            []
        );
    }
}
