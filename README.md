## ziggurat
An open source Zigbee stack implemented in Rust.

Traditional Zigbee coordinator firmware is written in C and is compiled to run self-contained
on a microcontroller. Ziggurat splits this architecture in two: we rely on a microcontroller
to manage the IEEE 802.15.4 radio (the wireless layer of both Zigbee and Thread) and move
all Zigbee processing and logic onto the host computer. This effectively turns the Zigbee
coordinator hardware into a simple radio that sends packets, receives packets, and automatically
sends IEEE 802.15.4 ACKs. Nothing more. All encryption, decryption, sending, retrying, routing,
logic, etc. is done on the host by Ziggurat.

Ziggurat requires low-level access to a Zigbee radio. Thankfully, there already exists
firmware that provides this out of the box: **OpenThread RCP**! The same firmware can
now be used for both Zigbee and Thread.

### Why

#### Speed
The most powerful Zigbee microcontrollers today have only a few hundred kilobytes of RAM
and maybe a megabyte of flash. Their Zigbee firmware is written with this resource-constrained
environment in mind: limited packet buffers, simpler routing algorithms, fewer concurrent
requests.

Ziggurat moves all of logic out of the microcontroller and onto the host, which has way
more than a few hundred kilobytes of RAM. Routing, discovery, and neighbor tables don't
need size limits. We can buffer an unlimited number of requests. We can keep track of
multiple concurrent routes to a single device and pick intelligently, reducing latency.

#### Openness
To compile firmware for a given Zigbee/Thread chip, you use a chip vendor's SDK.
For example, Silicon Labs [Simplicity SDK](https://github.com/SiliconLabs/simplicity_sdk).
These SDKs are a mix of pre-compiled libraries without source code and a bit of source code
to glue together the functions exported by the libraries. The interesting parts of a Zigbee
stack are locked away (e.g. how does routing work?). If there are bugs, the chip vendor decides
if and when a bug is worth fixing.

Ziggurat is entirely open source, both in licensing and source availability, and is
developed in the open. There are no closed-source binary blobs. OpenThread RCP uses a
standardized serial protocol and is effectively chip-agnostic, allowing Ziggurat to work
with any radio that supports OpenThread RCP.

#### Rust
Rust is memory safe and fast. It's also fun to write. Ziggurat is written in fairly performant
Rust to reduce the round trip latency when communicating with the radio hardware and to allow
it to run on even the most basic of hosts. Future development may get it running on
larger microcontrollers directly, like the ESP32.

### Setup
Ziggurat is in early alpha testing. Keep this in mind!

Ziggurat can be set up as a regular ZHA radio in **Home Assistant 2026.7.0** or newer.
1. Flash your Zigbee radio with OpenThread RCP firmware, the same firmware you use for Thread. Radios with Silicon Labs chips (e.g. EFR32MG21, EFR32MG24) are recommended but others should work too.
2. Install the Ziggurat server app from the [Zigpy app repo for Home Assistant](https://github.com/zigpy/addons).
3. Set up ZHA (or start a migration) and select "manual" as the serial port path. Type in `ws://local-ziggurat:9999` as the URL.
4. When ZHA asks for the radio type, pick **Ziggurat** and migrate your existing network (or set a new one up).
5. Done.

### Development
Ziggurat aims to implement the portions of a Zigbee stack used by normal Home Assistant
users, not the entire binder of Zigbee specification verbatim. It is nearly feature-complete
in terms of functionality exposed by consumer Zigbee devices:

- [x] 802.15.4, Zigbee APS, and Zigbee NWK layers are implemented, cryptography included
- [x] AODV routing (the default)
- [x] Route discovery
- [x] Source routing
- [x] Device joining
- [x] Child device message holding and management
- [ ] Zigbee Green Power (TODO)

Zigbee R23 and R23.1 support (i.e. Zigbee 4.0) are low on the list but planned for the
future. Keep in mind Zigbee is both forward and backward compatible and practically nothing
user-visible has changed in these revisions.

#### Testing
Ziggurat's public API is a simple WebSocket server, which can be run locally instead of
in a Home Assistant addon:

```bash
cargo run --bin ziggurat /dev/cu.SLAB_USBtoUART --baudrate 460800 --host 0.0.0.0:9999
```

The adapter itself is stateless and ZHA will push all network configuration to it on startup.


#### Future work
- Ziggurat currently statically allocates most protocol-level parsing buffers, there are only
  a few places left in the stack (e.g. `HashMap`) that rely on dynamic allocation. This is
  in preparation for eventually trying to run Ziggurat on a microcontroller directly, probably
  the ESP32-C6.
- For testing purposes (especially CI) it would be convenient to allow Ziggurat to have a
  dynamically configurable role on startup. Adding the ability to join a network as a router
  would allow for some useful end-to-end testing scenarios, like a synthetic Spinel layer
  that can connect multiple Ziggurat instances together.
- Zigbee Green Power.
- Exploring more routing algorithms.

---

<sup>An earlier iteration of this concept in Python is available as [zigpy-spinel](https://github.com/puddly/zigpy-spinel).</sup>
