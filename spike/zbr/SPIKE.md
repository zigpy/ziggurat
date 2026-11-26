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

# Sleepy end device (router placement)

Device: ESP32-C6 `c6-devkits/c6-f9c4` (taken from the ZLOE bench at the user's request) with
zbpeer rebuilt as a sleepy end device (`sleepy-zbpeer.patch` against spinel2quic `zbpeer`):
receiver off when idle, keepalive / data poll every 15 s (observed ~16 s), channel 15 only,
4 MB flash. It joined with the light (0x1f77) as parent, NWK 0x7bf9, capability 0x84.

`sleepy_probe.py`: a Read Attributes (ack requested) every 2 s for 60 s, 30 requests.

| Run | Gateway | Responses | Notes |
|---|---|---|---|
| 1 | `sleepy_destination` always false | 15/30 | 4 of the 19 nacks were false: `aps-ack-timeout` at 5 s, response at 5.5–7 s |
| 2 | flag set for devices whose Device_annce says rx off when idle | 16/30 | every ack matches a response; nack at 12.7 s means really lost |
| 3 | run 2 + one re-send after an APS ack timeout | 22/30 | nack at 25.4 s; latency up to 15 s |

## Learned

- The pattern is the parent's 7.68 s indirect queue against the device's poll interval: a frame
  sent within 7.68 s before a poll is delivered at that poll, anything earlier expires in the
  parent. With a 16 s poll, half of the requests sent at random times are lost.
- The gateway has to know which devices sleep: otherwise the APS ack timeout is too short and
  it nacks requests that do get answered. The Device_annce capability byte is one source (seen
  only on join/rejoin, lost on gateway restart); the node descriptor or the controller's
  database are others.
- One retry at the ack timeout helps but cannot cover the poll cycle: the retry's window starts
  12.7 s after the first, leaving ~5 s of every 16 s uncovered. Retrying at the persistence
  expiry (7.68 s) instead would cover it, at the cost of duplicate frames when the first ack is
  just late.
- In the router placement the gateway is not the parent, so it cannot see polls: no "deliver on
  next poll" mailbox. That needs the gateway to be the parent (coordinator placement, or
  devices joined through the gateway router), or the device to cooperate (Poll Control
  cluster check-ins + fast poll), or a client-visible "queued / expected delay" answer as the
  design note's nack-waiting flag intended.
- Reports from the sleepy device are unaffected by the poll: it transmits when it wakes. They
  did need the router to answer NWK_addr_req for itself (below).

## Functional run (`sed_steps.py`, client retries a nack up to 4 times)

- ZDO Bind (On/Off, to the router's EUI-64 ep 1) from IP: ok after 12.8 s; Configure
  Reporting: 0.25 s (the device fast-polls for a while after any exchange, so follow-ups answer
  in ~0.2 s). `sed-functional.log`; its On/Off frames were wrongly built (global, not cluster
  commands), fixed in the later runs.
- On / Read / Off / Read: every step done, some only on the client's 2nd or 3rd attempt (nack
  `aps-ack-timeout` at 25.4 s = first send + gateway re-send both expired). Latency 0.2–15 s.
  `sed-functional-2.log`.
- Reports did not arrive at first: to use the binding the device broadcasts NWK_addr_req for
  the router's EUI-64, and nobody answered (the router is not in the coordinator's address map
  the way a joined router would be). The router's ZDP responder now answers NWK_addr_req /
  IEEE_addr_req for itself; after that every executed toggle produced a multicast report within
  ~0.2 s of the response. `sed-functional-3.log`, `router-sed.log`.

## Soak (1 h, `soak.py` with 45 s interval, 30 s timeout)

`soak-sed.jsonl`, `soak-sed-summary.txt`, `soak-sed-rss.log`. Each cycle: toggle (ack, Default
Response, report), then read back. No client retries.

| | n | p50 | p90 | max |
|---|---|---|---|---|
| toggle ack | 46/80 | 5.2 s | 13.9 s | 15.0 s |
| report | 44/80 | 5.3 s | 14.0 s | 15.1 s |
| read response | 79/80 | 0.3 s | 13.9 s | 15.0 s |

- 44/80 cycles fully ok. 34 toggles nacked `aps-ack-timeout`; in each the device state stayed
  unchanged (read back the old value), so these were real losses, not false nacks. 2 executed
  toggles produced no report. RSS steady at 13–14 MB.
- The failures come in runs (cycles 1–13, 36–55, 79): the 45 s interval is close to 3 poll
  periods, so the send phase drifts slowly through the poll cycle. Losses happen when the first
  send and the re-send 12.7 s later both expire before a poll, i.e. a poll lands in the 7.7–12.7
  s gap after the send. The read sent right after such a nack lands just before the next poll,
  which is why reads succeed (p50 0.3 s) in exactly the cycles where toggles fail.
- Confirms the earlier learning: re-sending at the persistence expiry (every 7.68 s for one poll
  period) would close the gap; a single re-send at the ack timeout cannot.

## Re-send every 7.68 s (soak, same setup)

The gateway now re-sends a frame for a sleepy device at 7.68 s and 15.36 s after the first send
(the parent's persistence time), each copy with the first copy's APS counter so the device's
duplicate rejection drops extras, until one copy is acked. The three copies cover a poll period up
to ~23 s. `soak-sed-resend.jsonl`, `soak-sed-resend-summary.txt`, `router-sed-resend.log`,
`sed-resend-functional.log`.

| | n | p50 | p90 | max |
|---|---|---|---|---|
| toggle ack | 80/80 | 7.8 s | 13.8 s | 15.1 s |
| report | 80/80 | 7.8 s | 13.9 s | 15.2 s |
| read response | 80/80 | 0.3 s | 0.4 s | 16.9 s |

- 80/80 cycles fully ok, no nacks, no wrong read-back, no duplicate execution. ~42 cycles needed
  the first re-send, ~1 the second. RSS steady at 14 MB.
- The p50 rises from 5.2 s to 7.8 s only because commands that used to be lost now land at the
  next poll. Without the gateway being the parent, this is the best the router placement does:
  latency up to one poll period, but no losses.
