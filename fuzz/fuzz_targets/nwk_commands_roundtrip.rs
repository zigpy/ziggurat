#![no_main]

use core::fmt::Debug;
use libfuzzer_sys::fuzz_target;
use ziggurat_zigbee::Command;
use ziggurat_zigbee::nwk::commands::{
    NwkEndDeviceTimeoutRequestCommand, NwkEndDeviceTimeoutResponseCommand, NwkLeaveCommand,
    NwkLinkPowerDeltaCommand, NwkLinkStatusCommand, NwkNetworkCommissioningRequestCommand,
    NwkNetworkCommissioningResponseCommand, NwkNetworkReportCommand, NwkNetworkStatusCommand,
    NwkNetworkUpdateCommand, NwkRejoinRequestCommand, NwkRejoinResponseCommand,
    NwkRouteRecordCommand, NwkRouteReplyCommand, NwkRouteRequestCommand,
};

// A command that parses must survive serialize/re-parse unchanged. Serialization
// may fail (a parsed list can exceed the on-air buffer), which is fine; what must
// not happen is a panic or a value that re-parses differently.
fn roundtrip<T: Command + PartialEq + Debug>(data: &[u8]) {
    if let Ok(command) = T::deserialize(data)
        && let Ok(bytes) = command.serialize()
    {
        let reparsed = T::deserialize(&bytes).expect("re-parsing our own serialization");
        assert_eq!(command, reparsed, "round-trip changed the command");
    }
}

fuzz_target!(|data: &[u8]| {
    roundtrip::<NwkRouteRequestCommand>(data);
    roundtrip::<NwkRouteReplyCommand>(data);
    roundtrip::<NwkRouteRecordCommand>(data);
    roundtrip::<NwkLinkStatusCommand>(data);
    roundtrip::<NwkNetworkReportCommand>(data);
    roundtrip::<NwkLinkPowerDeltaCommand>(data);
    roundtrip::<NwkRejoinRequestCommand>(data);
    roundtrip::<NwkRejoinResponseCommand>(data);
    roundtrip::<NwkLeaveCommand>(data);
    roundtrip::<NwkNetworkUpdateCommand>(data);
    roundtrip::<NwkEndDeviceTimeoutRequestCommand>(data);
    roundtrip::<NwkEndDeviceTimeoutResponseCommand>(data);
    roundtrip::<NwkNetworkStatusCommand>(data);
    roundtrip::<NwkNetworkCommissioningRequestCommand>(data);
    roundtrip::<NwkNetworkCommissioningResponseCommand>(data);
});
