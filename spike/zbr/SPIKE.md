# SPIKE (throwaway): Zigbee Border Router, coordinator (A) and router (B) placements

Design note: `docs/superpowers/specs/2026-11-21-zigbee-border-router-design.md`.
Code: `crates/ziggurat-server/src/zbr.rs`, enabled with `--zbr-port <port>`
(`--zbr-policy read-only|commands|full`, `--zbr-multicast-interface <if>`).

## Setup (2026-11-21)

- Radio: ESP32-C6 `c6-devkits/c6-s2q-peer` flashed with stock OT RCP, Ziggurat as coordinator.
- zigpy (`network.py`, zigpy-ziggurat 1.2.1) forms the network and joins devices; no HA.
  Network: channel 15, PAN 0x2275, EPID bf:21:54:02:88:05:4e:3d.
- Device: ESP32-C6 `c6-devkits/c6-6403`, zbpeer ZBOSS on/off light, endpoint 10, EUI-64
  20:6e:f1:ff:fe:0a:e0:a0.
- Everything runs in a rootless network namespace (`ctl.sh start|stop|nsenter`, `inns.sh`):
  `ip -6 route add local fd00::/8 dev lo` (AnyIP) instead of RA, and a veth pair for the
  multicast group, because `lo` does not loop IPv6 multicast back.
- Derived prefix `fd9e:4994:3fb::/64`; the light is `fd9e:4994:3fb::226e:f1ff:fe0a:e0a0`;
  multicast group `ff35:40:fd9e:4994:3fb::1`; UDP port 23106.

## Results

All success criteria met (logs in this directory):

- On / Off / Read Attributes from `client.py` over UDP/IPv6: APS ack comes back as an `ack`
  header, the device's reply (Default Response, Read Attributes Response) comes back by unicast
  from the device's own address with the client's ZCL TSN restored.
- Policy `commands` nacks Configure Reporting and ZDO with `policy-denied`.
- Policy `full`: ZDO Bind_req (light On/Off -> coordinator) and Configure Reporting sent from
  IP succeed; afterwards each toggle produces attribute reports that arrive on the multicast
  group, sourced from the device's address, flagged `unsolicited`.
- zigpy ran alongside without warnings.

## Learned

- The attach point is small: subscribe to the server's notification hub, send through
  `proto::send_unicast`. No stack changes were needed.
- Sourcing from AnyIP-routed (unassigned) addresses through `IPV6_PKTINFO` needs
  `IPV6_FREEBIND`; without it `sendmsg` fails with EINVAL.
- Local multicast listeners on the gateway host need `SO_REUSEADDR` on both sockets.
- The TSN rewrite separates IP clients from each other but not from zigpy: zigpy picks its
  own TSNs and could collide with the gateway's. Router placement (spike B) avoids this.
- Profile is assumed (ZDO on endpoint 0, HA elsewhere); descriptor lookup is not done.
- A device's address is only known once Ziggurat's address map has it (zigpy loads it on
  start, joins add to it).
- The light sends two reports per change (its own report plus the configured one).

# Spike B: router placement

Code: `crates/ziggurat-server/src/zbr_router.rs`, enabled with `--zbr-router-of <ws url>` next to
the `--zbr-*` flags. Run: `PLACEMENT=router POLICY=full ./ctl.sh start` (the coordinator then runs
without the gateway).

## Setup (2026-11-21)

- Second radio: ESP32-C6 `c6-devkits/c6-d88c` (stock OT RCP), taken from the ZLOE bench's
  `zloe-sat2` (container stopped) at the user's request.
- The router fetches the network settings (key, PAN, channel) from the spike A coordinator's
  Ziggurat WebSocket and configures itself with `NodeRole::Router` (the ZLOE satellite spike's
  method, no over-the-air join), NWK 0x4965 derived from its EUI-64 `20:6e:f1:ff:fe:0a:d8:8c`.
  It sends Device_annce and answers Node_Desc / Active_EP itself; zigpy saw it join and
  interviewed it without warnings.

## Results

All success criteria met (`run-router-placement.log`, `router-gateway.log`):

- On / Read Attributes / Off through the router's gateway: ack, then the reply by unicast from
  the device's address, client TSN restored. Same wire behaviour as spike A.
- ZDO Unbind (light -> coordinator) and Bind (light -> router) from IP, then Configure Reporting:
  each toggle produces one report on the multicast group, now delivered to the router.
- Unknown EUI-64: the gateway broadcasts NWK_addr_req, waits 3 s, nacks `unknown-device`
  (`run-router-unknown-device.log`).

## Learned

- The router needed no stack changes either: `NodeRole::Router` in Configure is enough.
- The router already knew the light's NWK address from overheard traffic; NWK_addr_req
  discovery (and learning from NWK_addr_rsp / Device_annce) is the fallback for the rest.
- Reports reach the router only via a binding to it, so the gateway (or whoever sets it up)
  has to rebind devices away from, or in addition to, the network's controller. Rebinding
  takes reports away from the controller (ZHA would lose state updates); adding a second
  binding doubles the radio traffic.
- ZDP requests addressed to the router itself (the controller's interview of it) also reach
  the multicast group: the gateway should not forward frames for its own node.
- No TSN clash with zigpy: the router has its own NWK address, so replies come back to it.

# Soak (router placement, 1 h)

`soak-run.sh` / `soak.py`: every 5 s toggle the light (ack requested), read On/Off back and
wait for the multicast report. 720 cycles, all passed: no missing ack, reply or report, no nack,
no wrong value read back. Ziggurat RSS flat at ~14 MB for both processes; no new warnings in
Ziggurat or zigpy (`soak-router-1h-*`).

| Leg | p50 | p95 | p99 | max |
|---|---|---|---|---|
| Command ack | 34 ms | 42 ms | 44 ms | 76 ms |
| Command response | 51 ms | 63 ms | 72 ms | 83 ms |
| Multicast report | 89 ms | 141 ms | 149 ms | 156 ms |
| Read ack | 40 ms | 53 ms | 64 ms | 79 ms |
| Read response | 60 ms | 73 ms | 83 ms | 100 ms |
