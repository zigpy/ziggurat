# SPIKE (throwaway): Zigbee Border Router, coordinator placement (spike A)

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
