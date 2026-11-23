use crate::runtime::Runtime;
use ziggurat_ieee_802154::types::Eui64;
use ziggurat_phy::{Phy, RadioPhy};
use ziggurat_zigbee::aps::frame::{ApsDataFrame, ApsDeliveryMode};
use ziggurat_zigbee::nwk::frame::{NwkFrame, is_broadcast};
use ziggurat_zigbee::zcl::endpoints::{BROADCAST_ENDPOINT, Endpoint, Indication};

use super::{ApsAck, RouteDirective, TxPriority, ZigbeeStack};

impl<P: RadioPhy, S: Phy, R: Runtime> ZigbeeStack<P, S, R> {
    /// Serve an application endpoint from the stack, rather than the client. Its
    /// simple descriptor joins the ones ZDP requests read.
    pub fn add_application_endpoint(&self, endpoint: Endpoint) {
        let mut core = self.core();
        core.descriptors.add_endpoint(endpoint.simple_descriptor());
        core.endpoints.add(endpoint);
    }

    /// Carry out a ZCL frame for the endpoints the stack serves. Replies mirror the
    /// APS security of the frame; `aps_security` is the sender's EUI64 if it was
    /// APS-secured. The client still observes the frame.
    pub(super) fn handle_zcl_frame(
        &self,
        nwk_frame: &NwkFrame,
        aps_frame: &ApsDataFrame,
        aps_security: Option<Eui64>,
    ) {
        // Group frames carry no endpoint, and we serve no groups
        let Some(destination_endpoint) = aps_frame.destination_endpoint else {
            return;
        };

        let replies = {
            let mut core = self.core();

            if destination_endpoint != BROADCAST_ENDPOINT
                && !core.endpoints.contains(destination_endpoint)
            {
                return;
            }

            let indication = Indication {
                source: nwk_frame.nwk_header.source,
                source_endpoint: aps_frame.source_endpoint,
                destination_endpoint,
                profile_id: aps_frame.profile_id,
                cluster_id: aps_frame.cluster_id,
                unicast: aps_frame.frame_control.delivery_mode == ApsDeliveryMode::Unicast
                    && !is_broadcast(nwk_frame.nwk_header.destination),
                aps_secured: aps_security.is_some(),
                asdu: &aps_frame.asdu,
            };

            core.endpoints.receive(&indication, self.core_now())
        };

        for reply in replies {
            if let Err(err) = self.send_aps_unicast(
                reply.destination,
                reply.profile_id,
                reply.cluster_id,
                reply.source_endpoint,
                reply.destination_endpoint,
                ApsAck::None,
                None,
                0,
                reply.asdu.to_vec(),
                aps_security,
                false,
                TxPriority::UserNormal,
                RouteDirective::StackDecides,
            ) {
                tracing::warn!(
                    "Failed to send a ZCL reply to {:?}: {err}",
                    reply.destination
                );
            }
        }
    }
}
