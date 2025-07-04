use tokio::time::Instant;

use ieee_802154::types::Nwk;

pub type RequestId = u8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Active = 0,
    DiscoveryUnderway = 1,
    DiscoveryFailed = 2,
    Inactive = 3,
}

#[derive(Debug)]
pub struct TableEntry {
    /// Destination address the routing table entry is for
    pub destination: Nwk,
    pub status: Status,

    /// A flag indicating that the destination indicated by this address does not store
    /// source routes.
    pub no_route_cache: bool,

    /// A flag indicating that the destination is a concentrator that issued a
    /// many-to-one route request.
    pub many_to_one: bool,

    /// A flag indicating that a route record command frame SHOULD be sent to the
    /// destination prior to the next data packet.
    pub route_record_required: bool,

    /// When set to TRUE, this flag indicates that an expected regular many-to-one route
    /// request was missed, i.e. the last many-to-one route request for this destination
    /// was received more than `nwkConcentratorDiscoveryTime` + `nwkRouteDiscoveryTime`
    /// seconds ago. When the entry is created, this field is initially set to FALSE.
    /// This flag only has meaning for entries, which have the many-to-one field set to
    /// TRUE.
    pub expired: bool,

    /// Used for `TLVs` and a few subsequent fields
    pub sequence_number_valid: bool,

    /// The 16-bit network address of the next hop on the way to the destination.
    /// This is the routing table entry's primary purpose.
    pub next_hop_address: Nwk,

    /// The 16-bit sequence number associated with this entry, obtained from the last
    /// route message that successfully updated this entry and conveyed a sequence
    /// number. Notice that routers prior to `R23` did neither maintain nor convey a
    /// sequence number. The value stored in this field is only valid if the Sequence
    /// Number Valid flag is set.
    pub sequence_number: u16,

    /// A 32-bit saturating counter, which is incremented whenever this routing table
    /// entry is used to forward a data packet towards its destination
    pub total_usage_count: u32,

    /// An 8-bit saturating counter, which is pre-loaded with `nwkRouterAgeLimit` when the
    /// routing table entry is created; incremented whenever this routing table entry is
    /// used to forward a state packet towards its destination; and decremented
    /// unconditionally once every `nwkLinkStatusPeriod`. A value of 0 indicates no
    /// packets have recently been forwarded along this route.
    pub recent_activity: u8,
}

#[derive(Debug)]
pub struct DiscoveryEntry {
    /// A sequence number for a route request command frame that is incremented each time
    /// a device initiates a route request. Notice that this 8-bit identifier is
    /// distinct from the 16-bit Routing Sequence Number. The former is used to discern
    /// route requests originating in a particular router; the latter is used to
    /// identify stale routing information.
    pub route_request_id: RequestId,
    /// The 16-bit network address of the route request’s initiator.
    pub source_address: Nwk,
    /// The 16-bit network address of the device that has sent the most recent lowest
    /// cost route request command frame corresponding to this entry’s route request
    /// identifier and source address. This field is used to determine the path that an
    /// eventual route reply command frame SHOULD follow.
    pub sender_address: Nwk,
    /// The accumulated path cost from the source of the route request to the current
    /// device.
    pub forward_cost: u8,
    /// The accumulated path cost from the current device to the destination device.
    pub residual_cost: u8,
    /// A countdown timer indicating the number of milliseconds until route discovery
    /// expires. The initial value is `nwkcRouteDiscoveryTime`.
    pub expiration_time: Instant,
    /// The 16-bit network address of the device this route discovery entry is
    /// identifying a route for. This isn't mentioned in the spec as being a required
    /// field.
    pub destination_address: Nwk,
}
