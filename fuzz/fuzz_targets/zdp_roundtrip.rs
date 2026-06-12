#![no_main]

use core::fmt::Debug;
use libfuzzer_sys::fuzz_target;
use zigbee::zdp::{
    DeviceAnnce, MgmtLqiReq, MgmtLqiRsp, MgmtRtgReq, MgmtRtgRsp, ParentAnnce, ParentAnnceRsp,
    ZdpCommand,
};

fn roundtrip<T: ZdpCommand + PartialEq + Debug>(data: &[u8]) {
    if let Ok((tsn, command)) = T::deserialize(data)
        && let Ok(bytes) = command.serialize(tsn)
    {
        let (tsn2, reparsed) = T::deserialize(&bytes).expect("re-parsing our own serialization");
        assert_eq!((tsn, command), (tsn2, reparsed), "round-trip changed the command");
    }
}

fuzz_target!(|data: &[u8]| {
    roundtrip::<DeviceAnnce>(data);
    roundtrip::<ParentAnnce>(data);
    roundtrip::<ParentAnnceRsp>(data);
    roundtrip::<MgmtLqiReq>(data);
    roundtrip::<MgmtLqiRsp>(data);
    roundtrip::<MgmtRtgReq>(data);
    roundtrip::<MgmtRtgRsp>(data);
});
