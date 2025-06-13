## ziggurat
An **experimental** open source Zigbee stack implemented in Rust[^1].

This project aims to replace the functionality provided by existing radio adapters running Zigbee firmware and move all processing to the host, eliminating practically all limitations imposed by microcontroller-based Zigbee stacks.

Existing Zigbee applications (i.e. ZHA, Z2M, and OpenHAB) would implement a new radio type and communicate with the Ziggurat server over TCP, a UNIX socket, or possibly a virtual serial port, using a high-level wire protocol similar to that of existing Zigbee stacks.


### Architecture
Ziggurat communicates with a 802.15.4 radio hardware over the OpenThread Spinel serial protocol. We currently use OpenThread RCP firmware to just send & receive packets and automatically send 802.15.4 ACKs. The stack handles all encryption, decryption, and processing, treating the radio hardware as just an 802.15.4 frontend. We aim to use with OpenThread RCP firmware for the foreseeable future, as it provides a uniform and hardware-agnostic 802.15.4 frontend that theoretically runs on chips from every major vendor and eliminates the need to use multiple firmwares when switching between Zigbee and Thread applications.

The wire format is provisional and *will* change. Currently, commands and responses are sent line-by-line as JSON for maximum debuggability.


### Setup
Start the TCP server and attach it to a port:

```bash
cargo run --bin ziggurat /dev/cu.SLAB_USBtoUART 0.0.0.0:9999
```

A single-file radio library for zigpy and demo client can be run to test the server by taking over an existing Zigbee network with hard-coded settings, re-interviewing an existing device on the network, and finally toggling its relay indefinitely in a tight loop:

```bash
python src/tools/zigpy_client.py 127.0.0.1:9999
```


### Status
- [x] 802.15.4, Zigbee APS, and Zigbee NWK layers are implemented, cryptography included
- [x] Rudimentary network management is implemented, allowing for simple one-hop networks to be controlled:
  - [x] Link status broadcasts
  - [x] Route discovery replies
  - [x] APS ACKs
- [ ] Multi-hop route calculation
- [ ] Route discovery
- [ ] Device joining
- [ ] Child device message holding and management

[^1]: An earlier iteration in Python is available as [zigpy-spinel](https://github.com/puddly/zigpy-spinel).
