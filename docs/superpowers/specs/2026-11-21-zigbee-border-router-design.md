# Zigbee Border Router: what it is (pre-spike description)

Status: exploration. Agreed in conversation on 2026-11-21; the spikes below are throwaway.

## What it is

A gateway that makes every device on a Zigbee network reachable over IPv6 so that anyone with a
UDP socket can talk to it in **raw ZCL**, without a Zigbee radio, zigpy or a vendor SDK.
Modelled on Z-Wave's Z/IP (per-node IPv6 + raw command bytes over UDP) and on how an OpenThread
Border Router publishes a Thread network on the LAN.

- **Addressing:** each device is `<prefix>::<EUI-64>`. The gateway owns one /64, a ULA derived
  deterministically from the network's Extended PAN ID (`fd` + first 40 bits of
  SHA-256("zigbee-br" ‖ EPID), subnet 0). The address survives rejoins and NWK address changes;
  the gateway resolves EUI-64 → NWK internally (Zigbee's own EUI-64/NWK split plays the role of
  Thread's ML-EID/RLOC16). Announced on the LAN with an RA Route Information Option, like OTBR.
- **Transport:** UDP, one fixed well-known port.
- **Frame:** small mandatory header (flags: ack-requested / ack / nack / nack-waiting; sequence
  number; destination endpoint; cluster; profile, 0 = from the endpoint's simple descriptor),
  optional TLV extensions (manufacturer code, group addressing, expected delay for sleepy
  devices), then the raw ZCL frame. Header field order mirrors APS so a Wireshark Lua dissector
  can hand off to the built-in ZCL dissector.
- **The gateway owns everything below ZCL:** APS framing and counters, fragmentation, source
  endpoint, routing, security. It never interprets ZCL.
- **Replies** to a client's request go back to that client by unicast.
- **Reports and other unsolicited frames** go to one multicast group per network, RFC 3306
  unicast-prefix-based (`ff35:40:<the /64>::1`), sent from the device's own address with the
  same header. No subscriber state.
- **Policy:** a configurable whitelist of what IP clients may send, with presets
  `read-only` (default), `commands`, `full`. Rejected sends get a nack with a policy status.

## What it is not

- Not an IP stack on Zigbee devices and not packet routing: devices have no IP, the gateway
  stands in for them.
- Not a re-encoding of ZCL (no CoAP/CBOR "Dotdot", no JSON/MQTT model, no Matter bridge).
- Not a network owner for now: ZHA (or whatever controller runs the network) keeps forming,
  joining, interviewing and configuring devices. A standalone mode, where Ziggurat persists the
  network itself, is a later, separate project.
- Not secured in the spikes (plain UDP on the LAN is an open actuator; DTLS-PSK is a later
  question).

## Two placements, both spiked

- **A. Coordinator:** inside ziggurat-server next to the zigpy client. Mirrors every received
  APS frame, rewrites the ZCL sequence number on IP-originated sends to avoid clashing with
  zigpy, snoops simple descriptors from zigpy's interviews, applies the policy.
- **B. Router:** Ziggurat joined to someone else's network as a router (spike: preconfigured
  network key, as the ZLOE satellite spike does; real joining later). Has its own NWK address,
  so replies come straight back with no clash; queries descriptors itself; sees reports only
  via a binding it adds. Works with any coordinator.

## First buildable step

Throwaway spikes on branch `zbr-spike` (worktree `~/dev/ziggurat-wt/zbr-spike`, off
`upstream/dev`):

1. Shared part: ULA derivation, EUI-64 → NWK lookup, UDP socket serving the whole /64 (Linux
   AnyIP local route + `IPV6_PKTINFO`, no TUN, static route on the client instead of RA),
   header codec, multicast copy.
2. Spike A on its own Zigbee network: a free ESP32-C6 as OT RCP radio for Ziggurat as
   coordinator, a small zigpy script forming the network and joining the `c6-6403` on/off light,
   then turning the light on and reading On/Off from `nc`/Python over IPv6.
3. Spike B on the same network: a second radio (another free C6 or the nRF52840 Pro Micro as
   OT RCP) running Ziggurat as router, doing the same.

Success: a ZCL On command and a Read Attributes round trip over UDP/IPv6 in both placements,
and a report from the light arriving on the multicast group.

## Open, for after the spikes

- Wire details: exact port number, header byte layout, nack status codes.
- Groups and broadcast addressing.
- mDNS/DNS-SD per device and endpoint (`_zigbee._udp`).
- Security (DTLS-PSK or LAN-only binding).
- Real joining for router mode; standalone mode; whether any of this goes upstream.
