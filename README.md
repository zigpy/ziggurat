## ziggurat
An **experimental** open source Zigbee stack implemented in Rust.

This project aims to replace the functionality provided by existing radio adapters running Zigbee firmware and move all processing to the host, eliminating practically all limitations imposed by microcontroller-based Zigbee stacks.

Existing Zigbee applications (i.e. ZHA, Z2M, and OpenHAB) would implement a new radio type and communicate with the Ziggurat server over TCP, a UNIX socket, or possibly a virtual serial port, using a high-level wire protocol similar to that of existing Zigbee stacks.

### Architecture
Ziggurat communicates with a 802.15.4 radio hardware over the OpenThread Spinel serial protocol. We currently use OpenThread RCP firmware to just send & receive packets and automatically send 802.15.4 ACKs. The stack handles all encryption, decryption, and processing, treating the radio hardware as just an 802.15.4 frontend. We aim to use with OpenThread RCP firmware for the foreseeable future, as it provides a uniform and hardware-agnostic 802.15.4 frontend that theoretically runs on chips from every major vendor and eliminates the need to use multiple firmwares when switching between Zigbee and Thread applications.

### Status
A few tools exist to test functionality but there is currently no server binary:

```bash
# Rapidly send 802.15.4 beacon requests on channel 19 and print timing information
cargo run --bin ziggurat-sender /dev/cu.SLAB_USBtoUART

# Capture traffic on channel 19 and dissect the 802.15.4, Zigbee APS, and NWK layers
cargo run --bin ziggurat-capture /dev/cu.SLAB_USBtoUART

# Parse a PCAP file with loaded Wireshark Zigbee network keys, printing decryption and parsing statistics
cargo run --bin ziggurat-pcap capture.pcap

# Capture and decrypt traffic on channel 25 with hardcoded network information,
# performing rudimentary security processing (NWK->IEEE mapping and rollback protection)
cargo run --bin ziggurat-network-sniffer /dev/cu.SLAB_USBtoUART
```

### TODO
- [x] A majority of 802.15.4 and the Zigbee APS and NWK layers are implemented, cryptography included.
- [x] The stack is able to reliably send and receive 802.15.4 frames (limited to about 200 per second).
- [ ] The wire protocol is not yet implemented. We have no significant latency limitations so for clarity and ease of implementation in downstream applications, Protobuf will probably be used.
- [ ] The Zigbee stack itself is not yet implemented, so we need to keep track of the NIB, implement routing, child management, and state persistence (likely via SQLite).
