import asyncio
import json
import itertools
import logging
import time

import zigpy.serial
import zigpy.application
import zigpy.types as t
import zigpy.zdo.types as zdo_t
from zigpy.state import NetworkInfo, NodeInfo, Key

_LOGGER = logging.getLogger(__name__)


class ZigguratProtocol(zigpy.serial.SerialProtocol):
    def __init__(self, on_async_event):
        super().__init__()

        self.on_async_event = on_async_event
        self.tid = 1
        self.pending_requests: Dict[int, asyncio.Future] = {}

    def data_received(self, data: bytes):
        super().data_received(data)

        while b"\n" in self._buffer:
            line, self._buffer = self._buffer.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue

            # Parse JSON
            try:
                msg = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as e:
                _LOGGER.debug("Failed to parse line as JSON: %r: %r", line, e)
                continue

            self.handle_message(msg)

    def handle_message(self, message: dict):
        tid = message.get("tid", 0)
        _LOGGER.debug("Received: %r", message)

        if tid == 0:
            # Asynchronous event
            self.on_async_event(message)
            return

        # Response to a pending request
        fut = self.pending_requests.pop(tid, None)
        if not fut or fut.done():
            _LOGGER.debug(f"Received response for unknown or finished TID={tid}: {message}")
            return

        fut.set_result(message)

    def connection_lost(self, exc):
        for tid, fut in self.pending_requests.items():
            if not fut.done():
                fut.set_exception(ConnectionError("Connection lost"))

        self.pending_requests.clear()
        super().connection_lost(exc)

    async def send_command(self, cmd: str, data: dict) -> dict:
        tid = self.tid
        self.tid = (self.tid + 1) & 0xFFFFFFFF

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self.pending_requests[tid] = fut

        message = {
            "tid": tid,
            "cmd": cmd,
            "data": data,
        }
        line = json.dumps(message) + "\n"
        _LOGGER.debug("Sending: %r", line)
        self._transport.write(line.encode("utf-8"))

        return await fut


class ZigguratControllerApplication(zigpy.application.ControllerApplication):
    def __init__(self, config):
        super().__init__(config)
        self._api = None

    async def connect(self):
        _, api = await zigpy.serial.create_serial_connection(
            loop=asyncio.get_running_loop(),
            protocol_factory=lambda: ZigguratProtocol(self.on_async_event),
            url=self._config[zigpy.config.CONF_DEVICE][zigpy.config.CONF_DEVICE_PATH],
        )
        await api.wait_until_connected()
        self._api = api

    async def disconnect(self):
        if self._api is not None:
            try:
                await self._api.disconnect()
            finally:
                self._api = None

    async def start_network(self):
        network_info = NetworkInfo(
            extended_pan_id=t.ExtendedPanId.convert("3a:9f:44:01:0b:3c:cb:93"),
            pan_id=t.PanId(0x4072),
            nwk_update_id=0,
            nwk_manager_id=t.NWK(0x0000),
            channel=t.uint8_t(20),
            channel_mask=t.Channels.from_channel_list([20]),
            security_level=t.uint8_t(5),
            network_key=Key(
                key=t.KeyData.convert(
                    "ee:83:0c:e4:85:57:9c:8c:b1:3f:87:00:b6:5d:4b:e8"
                ),
                seq=0,
                tx_counter=((int(time.time()) - 1742079562) * 1000),
            ),
            tc_link_key=Key(
                key=t.KeyData(b"ZigBeeAlliance09"),
                partner_ieee=t.EUI64.convert("bc:02:6e:ff:fe:24:db:90"),
                tx_counter=0,
            ),
            key_table=[],
            children=[],
            nwk_addresses={},
            stack_specific={},
            metadata={},
        )

        node_info = NodeInfo(
            ieee=t.EUI64.convert("bc:02:6e:ff:fe:24:db:90"),
            nwk=t.NWK(0x0000),
            logical_type=zdo_t.LogicalType.Coordinator,
        )

        await self.write_network_info(network_info=network_info, node_info=node_info)

    async def force_remove(self, dev):
        _LOGGER.debug("Not implemented")

    async def add_endpoint(self, descriptor):
        _LOGGER.debug("Not implemented")

    async def permit_ncp(self, time_s: int = 60):
        _LOGGER.debug("Not implemented")

    async def permit_with_link_key(self, node, link_key, time_s: int = 60):
        _LOGGER.debug("Not implemented")

    async def write_network_info(self, *, network_info, node_info):
        await self._api.send_command(
            "set_network_settings",
            {
                "channel": network_info.channel,
                "nwk_update_id": network_info.nwk_update_id,
                "pan_id": network_info.pan_id.serialize()[::-1].hex(),
                "extended_pan_id": str(network_info.extended_pan_id),
                "nwk_address": node_info.nwk.serialize()[::-1].hex(),
                "ieee_address": str(node_info.ieee),
                "network_key": str(network_info.network_key.key),
                "network_key_seq": network_info.network_key.seq,
                # To avoid persisting state while also preventing counter rollback,
                # just base the counter on the current time
                "network_key_tx_counter": network_info.network_key.tx_counter,
            },
        )

    async def load_network_info(self, *, load_devices=False):
        pass

    async def reset_network_info(self):
        pass

    def on_async_event(self, event):
        if event["cmd"] == "received_aps_command":
            packet = t.ZigbeePacket(
                src=t.AddrModeAddress(
                    addr_mode=t.AddrMode.NWK,
                    address=t.NWK.deserialize(bytes.fromhex(event["data"]["source"]))[0],
                ),
                dst=t.AddrModeAddress(
                    addr_mode=t.AddrMode.NWK,
                    address=t.NWK(0x0000),
                ),
                src_ep=event["data"]["src_ep"],
                dst_ep=event["data"]["dst_ep"],
                profile_id=event["data"]["profile_id"],
                cluster_id=event["data"]["cluster_id"],
                lqi=event["data"]["lqi"],
                rssi=event["data"]["rssi"],
                data=t.SerializableBytes(bytes.fromhex(event["data"]["data"])),
            )
            self.packet_received(packet)

    async def send_packet(self, packet):
        assert packet.dst.addr_mode is t.AddrMode.NWK

        profile_id = 0x0000

        if packet.src_ep != 0 or packet.dst_ep != 0:
            profile_id = 0x0104

        await self._api.send_command(
            "send_aps_command",
            {
                "destination_nwk": packet.dst.address.serialize()[::-1].hex(),
                # "destination_eui64": "00:0d:6f:ff:fe:a4:f1:0b",
                "profile_id": profile_id,
                "cluster_id": packet.cluster_id or 0x0000,
                "src_ep": packet.src_ep,
                "dst_ep": packet.dst_ep,
                "aps_ack": t.TransmitOptions.ACK in packet.tx_options,
                "aps_seq": packet.tsn,
                "data": packet.data.serialize().hex(),
            },
        )


async def main(host, port):
    loop = asyncio.get_running_loop()

    app = ZigguratControllerApplication(
        {
            "device": {"path": f"socket://{host}:{port}"},
            "backup_enabled": False,
            "startup_energy_scan": False,
            "use_thread": False,
        }
    )

    await app.connect()
    await app.start_network()

    dev = app.add_device(nwk=0x26f4, ieee=t.EUI64.convert("00:0d:6f:ff:fe:a4:f1:0b"))
    await dev.schedule_initialize()

    while True:
        try:
            async with asyncio.timeout(1):
                await dev.endpoints[1].on_off.toggle()
        except asyncio.TimeoutError:
            _LOGGER.warning("Timed out...")


if __name__ == "__main__":
    import sys
    import coloredlogs
    coloredlogs.install(level=logging.DEBUG)

    host, port = sys.argv[1].split(":")
    port = int(port)

    asyncio.run(main(host, port))
