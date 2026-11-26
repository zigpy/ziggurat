"""SPIKE: zigpy in front of Ziggurat: form a network, let devices join, stay up."""
import asyncio, logging, sys
import zigpy.config as conf
from zigpy_ziggurat.zigbee.application import ControllerApplication

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
for noisy in ("zigpy_ziggurat", "zigpy.zcl", "zigpy.device"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

class Listener:
    def device_joined(self, device):
        print(f"JOINED {device.ieee} nwk=0x{device.nwk:04x}", flush=True)
    def device_initialized(self, device, *args):
        eps = {ep_id: sorted(f"0x{c:04x}" for c in ep.in_clusters) for ep_id, ep in device.endpoints.items() if ep_id}
        print(f"INITIALIZED {device.ieee} {device.manufacturer} {device.model} {eps}", flush=True)

async def main(url, db, channel, permit):
    app = await ControllerApplication.new(
        {conf.CONF_DEVICE: {conf.CONF_DEVICE_PATH: url}, conf.CONF_DATABASE: db,
         conf.CONF_NWK: {conf.CONF_NWK_CHANNEL: channel}},
        auto_form=True, start_radio=True)
    app.add_listener(Listener())
    s = app.state
    print(f"NETWORK channel={s.network_info.channel} pan=0x{s.network_info.pan_id:04x} epid={s.network_info.extended_pan_id}", flush=True)
    for dev in app.devices.values():
        print(f"KNOWN {dev.ieee} nwk=0x{dev.nwk:04x} {dev.model}", flush=True)
    if permit:
        await app.permit(permit)
        print(f"PERMIT {permit}s", flush=True)
    await asyncio.Event().wait()

asyncio.run(main(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])))
