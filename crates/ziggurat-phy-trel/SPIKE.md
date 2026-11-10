# SPIKE: ZLOE (Zigbee Link Over Ethernet), a TREL-like IP backbone, for satellite routers (zigpy/ziggurat#84)

Throwaway. Answers: can Ziggurat routers, configured out-of-band and linked to the
coordinator over IP, extend coverage without any NWK changes?

## How it works

- `TrelPhy<P>` wraps any `RadioPhy`. The backbone is a second "radio" that only
  reaches other Ziggurat nodes: raw 802.15.4 frames in UDP datagrams.
- Unicast to a backbone peer → UDP only, ack + 3×50 ms retries, falls back to the air.
  Broadcast → air **and** every peer (NWK broadcast dedup absorbs duplicates).
- Frames from peers are reported with LQI 255 (on either link), so NWK link cost to a
  peer is 1 and routing prefers the backbone.
- Peers: mDNS `_zloe._udp` (TXT `eui64`, `nwk`, `pan`, `v`), `--zloe-peer`,
  or learned from the first datagram. Different PAN → ignored.
- Satellite: `--zloe-satellite` finds the coordinator on the backbone like TREL peers find
  each other (mDNS TXT `role=coordinator`), fetches its settings with a
  `NETINFO_REQ`/`NETINFO_RSP` exchange over ZLOE and starts in router role. The
  backbone is treated as **trusted**: the settings, network key included, go
  unauthenticated to whoever asks. `--zloe-satellite-pan <hex>` picks a network when several
  coordinators are on the LAN; the satellite may start before the coordinator (it
  waits up to 60 s). `--zloe-satellite-of ws://coord:9999` (fetch via the coordinator's
  Ziggurat API) remains as a fallback. NWK address derived from the
  EUI64 (or `--zloe-satellite-nwk`). Frame counters seeded from the clock.
- `--deny <eui64|nwk>` fakes "out of radio range" (drops air frames from it, refuses
  air unicasts to it).
- Every 30 s with the backbone on: `[diag]` log lines with peers and router neighbours
  (LQA, incoming/outgoing cost).

## Bench

Coordinator (ZHA connects here as usual):

```bash
cargo run --bin ziggurat -- --device /dev/serial/by-id/<coord-c6> --listen 0.0.0.0:9999 \
  --zloe-port 19790
```

Satellite (same box is fine, different port/radio):

```bash
cargo run --bin ziggurat -- --device /dev/serial/by-id/<sat-c6> --listen 127.0.0.1:9998 \
  --zloe-port 19791 --zloe-satellite
```

Experiment:

1. Both up → `[diag]` shows each other as backbone peer, neighbour cost 1/1.
2. Pair an IKEA outlet via ZHA normally (through the coordinator).
3. Restart the coordinator with `--deny <outlet-eui64> --deny <outlet-nwk>`.
4. Toggle the outlet from ZHA; it must route coordinator → satellite (backbone) →
   outlet, and back. Watch `[diag]` on both and `Mgmt_Lqi` of the outlet.
5. Drop the deny list; observe which routes win and whether real routers'
   Link Status handling of two "coordinator-ish" neighbours causes trouble.

Loopback smoke tests (no hardware): `cargo test -p ziggurat-phy-trel`.

## Known gaps (by design for a spike)

- **Satellites can't join devices.** Router-side join (APS Update Device to the TC,
  unwrapping Tunnel commands) isn't implemented; pair through the coordinator first.
- **Deny list is approximate.** The RCP still hardware-ACKs frames from a denied
  device. Fine once routes are established; misleading for direct joins.
- No peer authentication (NWK frames are encrypted, but a LAN host could flood or
  replay). IPv4 only. No children on satellites. Satellite isn't announced to ZHA.

## ZLOE interface

`--zloe-interface <ifname>` confines the backbone to one interface: UDP binds that
interface's IPv4 address, mDNS runs only there and advertises only that address, and
peer addresses on the same subnet are preferred. Without it, all interfaces are used
(mDNS then advertises Docker bridges and loopback too). The old `--backbone-*` flag
names still work as aliases.

## Findings (bench, 2026-11-10)

Bench: coordinator and satellite are ESP32-C6 boards on stock OpenThread RCP (UART, no
flow control) driven by Ziggurat on one Linux host, ZLOE on `enp4s0f0`; two more
ESP32-C6 boards run an esp-zigbee-lib 2.1 (ZBOSS) on/off-light **router**
(spinel2quic `zbpeer`, 4 MB build) as third-party routers. Test network on channel 25.
Driven without ZHA: `--test-network` + `zloe-ctl`.

- **Discovery / bootstrap:** satellite started before the coordinator, found it over
  mDNS ~4 s after it came up, fetched settings over ZLOE and was a router 60 ms later.
  Backbone neighbours settle at cost 1/1 within one Link Status period.
- **mDNS advertises every interface** (Docker bridges, loopback): fixed by preferring
  LAN addresses and locking a peer to its datagrams' source; `--zloe-interface` confines
  everything to one NIC.
- **Out-of-range via the backbone works:** with the coordinator denying router `0xBDE5`,
  the coordinator source-routes through the satellite (`relays: [satellite]`), the
  satellite relays over the air. On/Off: 10/10 delivered, 42–74 ms to APS ack
  (median ~55 ms). Mgmt_Lqi round trip over the same path: 42 ms.
- **Direct path (no deny):** 10/10 over the air, 40–68 ms (median ~41 ms); the backbone
  is not used when the destination is a direct neighbour.
- **Third-party routers are not confused:** both ZBOSS routers list the coordinator and
  the satellite as ordinary sibling routers with plausible LQIs; nothing anomalous seen
  in their Link Status handling. (The overlapping-Link-Status worry applies to one node
  with several radios; a satellite is a separate node, so it does not arise.)
- **ESP RCP LQI is low:** boards centimetres apart report LQA ~10 (cost 7), so the
  backbone's cost 1 dominates route selection.
- **Unrelated upstream issues hit on the way:**
  - zigpy/ziggurat#88 (router joiners leave): worked around in the spike by delivering
    to router children directly.
  - Without zigpy nobody answers `Node_Desc_req`; ZBOSS joiners leave. `--test-network`
    answers it.
  - Host sends with radius 0 go out with radius 1 (clamped); a relayed hop then drops
    them ("radius is exhausted"). zigpy always sends a real radius, `zloe-ctl` now 30.

Not covered: satellites accepting joins (router-side join), children on satellites,
multiple satellites, Wi-Fi backbone under loss, restart/rejoin behaviour, real IKEA
devices.
