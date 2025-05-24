import asyncio
import json
import itertools
import pathlib
import logging
import time

import zigpy.serial
import zigpy.application
import zigpy.backups
import zigpy.types as t
import zigpy.zdo.types as zdo_t
from zigpy.exceptions import DeliveryError
from zigpy.state import NetworkInfo, NodeInfo, Key

_LOGGER = logging.getLogger(__name__)

FALLBACK_NETWORK_SETTINGS = zigpy.backups.NetworkBackup.from_dict(
    {
        "version": 1,
        "backup_time": "2025-05-18T15:51:45.589743+00:00",
        "network_info": {
            "extended_pan_id": "fe:ed:fa:ce:de:ad:be:ef",
            "pan_id": "BEEF",
            "nwk_update_id": 2,
            "nwk_manager_id": "0000",
            "channel": 25,
            "channel_mask": [
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                23,
                24,
                25,
                26,
            ],
            "security_level": 5,
            "network_key": {
                "key": "37:66:8f:d6:4e:35:e0:33:42:e5:ef:9f:35:cc:f4:ab",
                "tx_counter": 19398801,
                "rx_counter": 0,
                "seq": 0,
                "partner_ieee": "ff:ff:ff:ff:ff:ff:ff:ff",
            },
            "tc_link_key": {
                "key": "5a:69:67:42:65:65:41:6c:6c:69:61:6e:63:65:30:39",
                "tx_counter": 0,
                "rx_counter": 0,
                "seq": 0,
                "partner_ieee": "00:12:4b:00:1c:a1:b8:46",
            },
            "key_table": [],
            "children": ["28:2c:02:bf:ff:e7:ba:8c"],
            "nwk_addresses": {
                "28:2c:02:bf:ff:ea:05:68": "12D8",
                "28:2c:02:bf:ff:e7:ba:8c": "ED4B",
                "00:15:bc:00:33:00:76:9a": "C4C5",
                "00:0d:6f:00:03:57:f1:be": "0E0D",
                "00:15:bc:00:1a:10:8a:e5": "2477",
                "00:15:bc:00:44:01:11:f9": "6C9D",
            },
            "stack_specific": {
                "ezsp": {"hashed_tclk": "eb1bfcf9cb33d0d609c466c7a35df7a7"}
            },
            "metadata": {
                "ezsp": {
                    "stack_version": 13,
                    "can_burn_userdata_custom_eui64": False,
                    "can_rewrite_custom_eui64": True,
                    "flow_control": "hardware",
                }
            },
            "source": "bellows@0.45.0",
        },
        "node_info": {
            "nwk": "0000",
            "ieee": "00:12:4b:00:1c:a1:b8:46",
            "logical_type": "coordinator",
            "model": "Yellow v1.2",
            "manufacturer": "Nabu Casa",
            "version": "7.5.0.0 build 0",
        },
    }
)


class ZigguratProtocol(zigpy.serial.SerialProtocol):
    def __init__(self, on_async_event, on_disconnect):
        super().__init__()

        self.on_async_event = on_async_event
        self.on_disconnect = on_disconnect
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

            try:
                self.handle_message(msg)
            except Exception:
                _LOGGER.exception("Failed to handle message: %r", msg)
                continue

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
            _LOGGER.debug(
                f"Received response for unknown or finished TID={tid}: {message}"
            )
            return

        fut.set_result(message)

    def connection_lost(self, exc):
        self.on_disconnect(exc)

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

        rsp = await fut

        if rsp["data"]["status"] == "error":
            raise DeliveryError(
                f"Error sending command: {rsp.get('error', 'unknown error')}"
            )

        return rsp


class ControllerApplication(zigpy.application.ControllerApplication):
    def __init__(self, config):
        if not config["device"]["path"].startswith("socket://"):
            config["device"]["path"] = "socket://127.0.0.1:9999"

        super().__init__(config)
        self._api = None

    async def connect(self):
        _, api = await zigpy.serial.create_serial_connection(
            loop=asyncio.get_running_loop(),
            protocol_factory=lambda: ZigguratProtocol(self.on_async_event, self.connection_lost),
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
        self._get_network_settings()
        await self.write_network_info(
            network_info=self.state.network_info, node_info=self.state.node_info
        )

    async def load_network_info(self, *, load_devices=False):
        self._get_network_settings()

    def _get_network_settings(self):
        try:
            # Use the most recent backup from the zigpy database, if supported
            latest_backup = self.backups[-1]
        except IndexError:
            latest_backup = FALLBACK_NETWORK_SETTINGS.replace(
                network_info=FALLBACK_NETWORK_SETTINGS.network_info.replace(
                    network_key=FALLBACK_NETWORK_SETTINGS.network_info.network_key.replace(
                        tx_counter=((int(time.time()) - 1742079562) * 1000)
                    )
                )
            )
        else:
            latest_backup = latest_backup.replace(
                network_info=latest_backup.network_info.replace(
                    network_key=latest_backup.network_info.network_key.replace(
                        tx_counter=(
                            latest_backup.network_info.network_key.tx_counter + 100000
                        )
                    )
                )
            )

        self.state.network_info = latest_backup.network_info
        self.state.node_info = latest_backup.node_info

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

    async def reset_network_info(self):
        pass

    def on_async_event(self, event):
        if event["cmd"] == "received_aps_command":
            packet = t.ZigbeePacket(
                src=t.AddrModeAddress(
                    addr_mode=t.AddrMode.NWK,
                    address=t.NWK.deserialize(bytes.fromhex(event["data"]["source"]))[
                        0
                    ],
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
        profile_id = 0x0000

        if packet.src_ep != 0 or packet.dst_ep != 0:
            profile_id = 0x0104

        await self._api.send_command(
            "send_aps_command",
            {
                "delivery_mode": {
                    t.AddrMode.NWK: "unicast",
                    t.AddrMode.Group: "multicast",
                    t.AddrMode.Broadcast: "broadcast",
                }[packet.dst.addr_mode],
                "destination": packet.dst.address.serialize()[::-1].hex(),
                # "destination_eui64": "00:0d:6f:ff:fe:a4:f1:0b",
                "profile_id": profile_id,
                "cluster_id": packet.cluster_id or 0x0000,
                "src_ep": packet.src_ep,
                "dst_ep": packet.dst_ep or 0,
                "aps_ack": t.TransmitOptions.ACK in packet.tx_options,
                "radius": packet.radius or 30,
                "aps_seq": packet.tsn,
                "data": packet.data.serialize().hex(),
            },
        )


async def main(host, port):
    loop = asyncio.get_running_loop()

    app = ControllerApplication(
        {
            "device": {"path": f"socket://{host}:{port}"},
            "backup_enabled": False,
            "startup_energy_scan": False,
            "use_thread": False,
            "database_path": str(pathlib.Path(__file__).parent.parent.parent.parent.parent / "zigbee.db"),
        }
    )
    await app._load_db()

    await app.connect()
    await app.start_network()

    await asyncio.sleep(100000)

    '''
    dev = app.add_device(nwk=0x26F4, ieee=t.EUI64.convert("00:0d:6f:ff:fe:a4:f1:0b"))
    await dev.schedule_initialize()

    while True:
        try:
            async with asyncio.timeout(1):
                await dev.endpoints[1].on_off.off()
        except asyncio.TimeoutError:
            _LOGGER.warning("Timed out...")
    '''


if __name__ == "__main__":
    import sys
    import coloredlogs

    coloredlogs.install(level=logging.DEBUG)
    logging.getLogger("aiosqlite").setLevel(logging.INFO)

    host, port = sys.argv[1].split(":")
    port = int(port)

    asyncio.run(main(host, port))
