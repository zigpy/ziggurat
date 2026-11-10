# SPIKE: TREL-like IP backbone for satellite routers (zigpy/ziggurat#84)

Throwaway. Answers: can Ziggurat routers, configured out-of-band and linked to the
coordinator over IP, extend coverage without any NWK changes?

## How it works

- `TrelPhy<P>` wraps any `RadioPhy`. The backbone is a second "radio" that only
  reaches other Ziggurat nodes: raw 802.15.4 frames in UDP datagrams.
- Unicast to a backbone peer → UDP only, ack + 3×50 ms retries, falls back to the air.
  Broadcast → air **and** every peer (NWK broadcast dedup absorbs duplicates).
- Frames from peers are reported with LQI 255 (on either link), so NWK link cost to a
  peer is 1 and routing prefers the backbone.
- Peers: mDNS `_zigtrel._udp` (TXT `eui64`, `nwk`, `pan`, `v`), `--backbone-peer`,
  or learned from the first datagram. Different PAN → ignored.
- Satellite: `--satellite-of ws://coord:9999` fetches `get_network_info` from the
  coordinator's Ziggurat API and starts in router role. NWK address derived from the
  EUI64 (or `--satellite-nwk`). Frame counters seeded from the clock.
- `--deny <eui64|nwk>` fakes "out of radio range" (drops air frames from it, refuses
  air unicasts to it).
- Every 30 s with the backbone on: `[diag]` log lines with peers and router neighbours
  (LQA, incoming/outgoing cost).

## Bench

Coordinator (ZHA connects here as usual):

```bash
cargo run --bin ziggurat -- --device /dev/serial/by-id/<coord-c6> --listen 0.0.0.0:9999 \
  --backbone-port 19790
```

Satellite (same box is fine, different port/radio):

```bash
cargo run --bin ziggurat -- --device /dev/serial/by-id/<sat-c6> --listen 127.0.0.1:9998 \
  --backbone-port 19791 --satellite-of ws://127.0.0.1:9999
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
