#![no_main]

use libfuzzer_sys::fuzz_target;
use ziggurat_zigbee::Command;
use ziggurat_zigbee::nwk::commands::{
    NwkEndDeviceTimeoutRequestCommand, NwkEndDeviceTimeoutResponseCommand, NwkLeaveCommand,
    NwkLinkPowerDeltaCommand, NwkLinkStatusCommand, NwkNetworkCommissioningRequestCommand,
    NwkNetworkCommissioningResponseCommand, NwkNetworkReportCommand, NwkNetworkStatusCommand,
    NwkNetworkUpdateCommand, NwkRejoinRequestCommand, NwkRejoinResponseCommand,
    NwkRouteRecordCommand, NwkRouteReplyCommand, NwkRouteRequestCommand,
};

fuzz_target!(|data: &[u8]| {
    let _ = NwkRouteRequestCommand::deserialize(data);
    let _ = NwkRouteReplyCommand::deserialize(data);
    let _ = NwkNetworkStatusCommand::deserialize(data);
    let _ = NwkRouteRecordCommand::deserialize(data);
    let _ = NwkRejoinRequestCommand::deserialize(data);
    let _ = NwkRejoinResponseCommand::deserialize(data);
    let _ = NwkLinkStatusCommand::deserialize(data);
    let _ = NwkLeaveCommand::deserialize(data);
    let _ = NwkNetworkReportCommand::deserialize(data);
    let _ = NwkNetworkUpdateCommand::deserialize(data);
    let _ = NwkEndDeviceTimeoutRequestCommand::deserialize(data);
    let _ = NwkEndDeviceTimeoutResponseCommand::deserialize(data);
    let _ = NwkLinkPowerDeltaCommand::deserialize(data);
    let _ = NwkNetworkCommissioningRequestCommand::deserialize(data);
    let _ = NwkNetworkCommissioningResponseCommand::deserialize(data);
});
