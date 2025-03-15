import asyncio
import json
import itertools
import time


class ZigguratProtocol(asyncio.Protocol):
    def __init__(self, on_connection_lost, on_async_event=None):
        self.on_connection_lost = on_connection_lost
        self.on_async_event = on_async_event

        self.transport = None
        self.buffer = b""

        self.tid = 1
        self.pending_requests: Dict[int, asyncio.Future] = {}

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport
        peername = transport.get_extra_info("peername")
        print(f"Connected to {peername}")

    def data_received(self, data: bytes):
        self.buffer += data

        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            line = line.strip()
            if not line:
                continue

            # Parse JSON
            try:
                msg = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as e:
                print("Failed to parse line as JSON:", line, e)
                continue

            self.handle_message(msg)

    def handle_message(self, message: dict):
        tid = message.get("tid", 0)

        if tid == 0:
            # Asynchronous event
            if self.on_async_event:
                self.on_async_event(message)
            else:
                print(f"[Async] {message}")
        else:
            # Response to a pending request
            fut = self.pending_requests.pop(tid, None)
            if fut and not fut.done():
                fut.set_result(message)
            else:
                print(f"Received response for unknown or finished TID={tid}: {message}")

    def connection_lost(self, exc):
        if exc:
            print("Connection lost due to error:", exc)
        else:
            print("Connection closed cleanly.")

        for tid, fut in self.pending_requests.items():
            if not fut.done():
                fut.set_exception(ConnectionError("Connection lost"))

        self.pending_requests.clear()
        self.on_connection_lost.set_result(True)

    async def send_command(self, cmd: str, data: dict = None) -> dict:
        if data is None:
            data = {}

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
        self.transport.write(line.encode("utf-8"))

        return await fut


async def main(host, port):
    loop = asyncio.get_running_loop()
    on_connection_lost = loop.create_future()

    def on_async_event(msg: dict):
        print(f"Event: {msg}")

    transport, protocol = await loop.create_connection(
        lambda: ZigguratProtocol(on_connection_lost, on_async_event=on_async_event),
        host,
        port,
    )

    try:
        resp = await protocol.send_command(
            "set_network_settings",
            {
                "channel": 20,
                "nwk_update_id": 0,
                "pan_id": "4072",
                "extended_pan_id": "3a:9f:44:01:0b:3c:cb:93",
                "nwk_address": "0000",
                "ieee_address": "bc:02:6e:ff:fe:24:db:90",
                "network_key": "ee:83:0c:e4:85:57:9c:8c:b1:3f:87:00:b6:5d:4b:e8",
                "network_key_seq": 0,
                # To avoid persisting state while also preventing counter rollback,
                # just base the counter on the current time
                "network_key_tx_counter": ((int(time.time()) - 1742079562) * 1000),
            },
        )

        # Device 0x26f4 (00:0d:6f:ff:fe:a4:f1:0b) joined the network
        seq = 0

        while True:
            seq = (seq + 1) % 256
            await protocol.send_command(
                "send_aps_command",
                {
                    "destination_nwk": "26f4",
                    # "destination_eui64": "00:0d:6f:ff:fe:a4:f1:0b",
                    "profile_id": 0x0104,
                    "cluster_id": 0x0006,  # OnOff
                    "src_ep": 1,
                    "dst_ep": 1,
                    "data": bytearray([0x01, seq, 0x02]).hex(),  # Toggle
                },
            )

        await on_connection_lost

    finally:
        print("Closing transport.")
        transport.close()


if __name__ == "__main__":
    import sys
    host, port = sys.argv[1].split(":")
    port = int(port)

    asyncio.run(main(host, port))
