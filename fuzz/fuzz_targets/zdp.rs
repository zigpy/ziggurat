#![no_main]

use libfuzzer_sys::fuzz_target;
use zigbee::zdp::{
    DeviceAnnce, MgmtLqiReq, MgmtLqiRsp, MgmtRtgReq, MgmtRtgRsp, ParentAnnce, ParentAnnceRsp,
    ZdpCommand,
};

fuzz_target!(|data: &[u8]| {
    let _ = DeviceAnnce::deserialize(data);
    let _ = ParentAnnce::deserialize(data);
    let _ = ParentAnnceRsp::deserialize(data);
    let _ = MgmtLqiReq::deserialize(data);
    let _ = MgmtLqiRsp::deserialize(data);
    let _ = MgmtRtgReq::deserialize(data);
    let _ = MgmtRtgRsp::deserialize(data);
});
