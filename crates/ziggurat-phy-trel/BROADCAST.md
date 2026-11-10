# ZLOE broadcast delivery: design and gap analysis

Status: design for the spike (zigpy/ziggurat#84). Step 1 is built: multicast
announcement (IPv6 and IPv4), broadcasts by multicast, the probe, and per-peer unicast
copies as the fallback (see "Step 1 as built"). Decision 2026-11-10: no hub and no
suppression. Peers on links where multicast is unreliable (Wi-Fi) run with
`--zloe-mcast-port 0`: they announce no group and get unicast copies.

Styleguide: the repository has no written styleguide; its conventions are enforced by
`.pre-commit-config.yaml` (`cargo fmt --all`, `cargo clippy --all-targets
--all-features -- -D warnings -Dclippy::all -Dclippy::nursery`). The spike follows
them. Tests stay at spike level (loopback smoke tests plus bench runs).

## Goal

Today a backbone node sends every 802.15.4 broadcast as one acked unicast datagram per
peer: N×(N−1) datagrams per flooded broadcast with N backbone nodes. The goal is fewer
datagrams without changing what the Zigbee stack sees, and without requiring multicast
to work.

## Algorithm

One rule: **every broadcast frame a backbone node transmits reaches every other
backbone node once, as that node's own frame** (802.15.4 source unchanged). The stack
then behaves exactly as it does on a radio channel: Link Status makes backbone nodes
neighbours, route requests are heard "directly", relays are real passive acks.

Three transports deliver that rule:

1. **Multicast** (primary): one unacknowledged datagram to the network's IPv6
   link-local group. N datagrams per flood (one per relaying node).
2. **Hub** (fallback, "hybrid star"): a satellite sends one acked datagram to the
   coordinator; the coordinator forwards it unchanged to every other backbone node.
   Unicast frames stay peer-to-peer.
3. **Direct** (last resort, what exists today): one acked datagram to each peer. Used
   when the coordinator does not answer.

Selection is per sender: a node uses multicast alone while every known peer keeps
acknowledging its multicast probes; otherwise it also uses the hub; if the hub does
not acknowledge, it sends directly.

**Optional suppression** (the "do not re-send to backbone routers" rule): a broadcast
received from the backbone is relayed on radio only. This cuts the hub fallback from
N×(N−1) to N−1 datagrams per flood, and is the only part that needs a stack change
(gaps S1–S5).

## Facts checked in the stack

- Passive-ack audience is every router neighbour with a live link:
  `Neighbors::expected_broadcast_relayers()` (`ziggurat-zigbee/src/nwk/neighbors.rs`),
  used in `ziggurat-driver/src/zigbee_stack/nwk.rs`. Quorum is
  `min(audience, broadcast_passive_ack_quorum = 8)`; below it a broadcast is re-sent
  `max_broadcast_retries = 2` times, `passive_ack_timeout = 500 ms` apart.
- A route request is only processed from a neighbour with a non-zero outgoing cost
  (`handle_route_request`), so backbone nodes must exchange Link Status to route
  through each other.
- Relayed route requests keep the originator's NWK source and sequence number; only
  path cost and radius change, and a strictly better cost is relayed again
  (`route.rs`). Relays are retried `rreq_retries = 2` times.
- Neighbours age out after `router_age_limit = 3` missed Link Status rounds of
  `link_status_period = 15 s`: 45 s.
- Relayed frames are re-secured by each hop (per-hop frame counter and source), so a
  relay cannot be forged without the network key.

## Gap analysis

Severity: **must** = the design is wrong without it; **minor**; **accepted** = known
limit of the spike; **open** = needs measurement.

### Multicast

| ID | Gap | Severity | Resolution |
|---|---|---|---|
| M1 | Nodes listen on different UDP ports (two nodes on one host on the bench); multicast needs one shared port. | must | Second socket on the multicast port with address and port reuse (built). Each node announces its group and port over mDNS; a sender uses one datagram per distinct announced address, normally one. Multicast is sent from the unicast socket, so receivers learn the sender's unicast address from it. |
| M2 | Link-local multicast is per interface; without `--zloe-interface` the interface is unknown. | must | Multicast only with `--zloe-interface` (built). A node without it announces no multicast address, so peers reach it through the fallback. |
| M3 | IPv4 multicast cannot be joined on the dual-stack socket. | resolved | Separate IPv4 socket joins `239.255.h.h` on the backbone interface's address; sending uses the unicast socket with `IP_MULTICAST_IF` set, so peers still see the unicast port. |
| M4 | Multicast can silently stop (snooping switch without a querier, Wi-Fi isolation), and can fail in one direction only. | must | Probe: one multicast datagram per 5 s carries the ack-request flag; peers answer by unicast. A peer that misses two probes is unconfirmed, and the sender adds the fallback. Detection ≤ 10 s, well inside the 45 s neighbour ageing. |
| M5 | Wi-Fi access points buffer multicast for sleeping clients and send it at the lowest rate. Expected +100–300 ms on broadcasts crossing the backbone. | open | Measure with a Wi-Fi satellite. Unicast is unaffected. |
| M6 | Multicast datagrams are unacknowledged. | covered | Each node receives up to N−1 copies of a flood (every relay), and Zigbee re-sends when passive acks are missing. |
| M7 | A node receives its own multicast (loopback must stay on for same-host peers). | covered | Already dropped by the sender-address check. |
| M8 | Any host on the segment can see headers (addresses, extended PAN ID) and inject datagrams. | accepted | Trusted backbone; group derived from the extended PAN ID plus the existing header check; payload stays NWK-encrypted. |
| M9 | Non-NWK broadcasts (beacon requests) are sent over the backbone today. | minor | Only 802.15.4 data frames go to the backbone. |

### Hub fallback

| ID | Gap | Severity | Resolution |
|---|---|---|---|
| H1 | Receivers overwrite a peer's IP address with the datagram's UDP source; a forwarded datagram would point every satellite at the coordinator. | must | "Forwarded" flag: receivers keep the sender's stored address and acknowledge the coordinator (hop by hop). The header already carries the original sender (extended and short address). |
| H2 | Satellites that reach the coordinator but not each other (Wi-Fi client isolation, firewall): they hear each other's Link Status through the hub and become neighbours, but direct unicast fails and falls back to radio. | must on such networks | The coordinator also forwards a unicast frame when direct delivery was not acknowledged; the destination is read from the inner 802.15.4 header (no new header field). Link quality reported for the peer follows the path used. |
| H3 | Coordinator down: Link Status between satellites stops, neighbours age out after 45 s and direct routes die. | must | No ack from the coordinator → send to every peer directly (transport 3). |
| H4 | Coordinator just restarted: it acknowledges but does not know every peer yet, so some broadcasts are not forwarded to all, and the sender cannot tell. | accepted | Lasts at most one Link Status round (15 s), under the 45 s ageing. |
| H5 | Without suppression the hub costs N×(N−1) datagrams per flood, as today; route-request relays up to 3× that. | accepted | Paid only where multicast fails. Suppression (below) is the alternative. |
| H6 | Forwarding loops. | covered | A datagram flagged forwarded is never forwarded again; duplicates are dropped by sender and packet number. |
| H7 | Any backbone host can make the coordinator send N−2 datagrams per datagram. | accepted | Trusted backbone. |

### Suppression (optional)

| ID | Gap | Severity | Resolution |
|---|---|---|---|
| S1 | Backbone nodes stop hearing each other's relays, so every node misses its passive-ack quorum and re-sends each broadcast twice, on radio too. ZLOE cannot forge the relays. | must | Stack change: leave backbone peers out of `expected_broadcast_relayers()`, with a way for the PHY to say who is a backbone peer. |
| S2 | ZLOE cannot tell a better-cost route request from a duplicate (same NWK source and sequence, cost encrypted). Suppressing it hides better paths, e.g. two satellites hear one device, one well and one badly. | must | Exempt NWK command frames (the frame type is readable): route discovery stays at N×(N−1). Or the stack tells the PHY which link the relayed copy arrived on (larger stack change, optimal). |
| S3 | Each backbone node gets exactly one copy of a flood: no redundancy against loss. | must | Never combine suppression with unacknowledged multicast; hub hops are acked. |
| S4 | Multicast expects passive acks from backbone peers, suppressed hub mode must not; the audience rule would change at runtime per peer. | must | Needs a per-peer transport state visible to the stack, or suppression in both modes (which conflicts with S3). |
| S5 | The "arrived from backbone" table needs a lifetime of at least `broadcast_delivery_time` (9 s) and must survive 8-bit sequence wrap. | minor | Timed entries keyed by NWK source and sequence. |

### Result

- Multicast and the hub fallback need **no stack change** and add no new Zigbee
  behaviour.
- Every hard gap (S1–S4) comes from suppression, which only improves the fallback
  path, and only on networks where multicast does not work.
- Without suppression the hub's total datagram count equals today's direct fan-out.
  What the hub adds is one datagram per broadcast for the satellite instead of N−1
  (matters for microcontroller or Wi-Fi satellites) and reachability between isolated
  satellites (H2).

Recommended order: (1) multicast + probe, with today's direct fan-out as the fallback;
(2) hub forwarding with H1–H3; (3) suppression only if measurements on a
multicast-hostile network show the fallback traffic is a problem.

## Wire changes

- Flags: bit 0 ack request (exists; on a multicast datagram it is the probe), bit 1
  "forward this" (satellite → coordinator), bit 2 "forwarded" (coordinator → peers).
- Multicast group: `ff12::5a4c:hhhh:hhhh` (transient, link-local scope), `h` = low 32
  bits of the extended PAN ID.
- Multicast port: `--zloe-mcast-port`, default 19789, 0 disables multicast.
- mDNS TXT `mc=[group]:port`: where the node listens for IPv6 multicast.
- IPv4 group: `239.255.h.h` (organization-local, RFC 2365), `h` = last two bytes of the
  extended PAN ID; TXT `mc4=239.255.h.h:port`.
- No new header fields: the original sender is already in the header, a forwarded
  unicast's destination is in the inner 802.15.4 header.

## Multicast announcement

Built. A node that can receive multicast joins the network's group on the backbone
interface and announces `mc=[ff12::5a4c:hhhh:hhhh]:port` in its `_zloe._udp` TXT
record. A node that cannot (no `--zloe-interface`, no IPv6, port 0) announces no `mc`.

- The announcement says a peer *can* receive multicast; the probe (M4) says whether
  it *does*. A peer without `mc` is never counted as reachable by multicast.
- Peers store the announced address scoped to their own backbone interface. It is
  cleared when the peer's mDNS record goes away.
- mDNS results are now kept while a node has no identity and applied once it has one:
  a satellite browses before it knows its network, and used to miss everything the
  coordinator announced.

Bench check: both nodes joined `ff12::5a4c:f5d9:7c12` on `enp4s0f0` (kernel shows two
users, two sockets on port 19789), each lists the other's `mc`, and a test datagram
sent to the group reached both.

## Step 1 as built

- A broadcast goes out as one multicast datagram to each distinct group of peers whose
  multicast is confirmed, plus a unicast copy (same packet number) to every other peer.
  Receivers keep one copy per sender and packet number.
- Only 802.15.4 data frames go to the backbone; beacon requests stay on the radio (M9).
- Probe: every 5 s an empty `KIND_PROBE` datagram (kind 4) is multicast with the
  ack-request flag; each peer answers with a unicast ack. A peer is confirmed while it
  has acked a probe in the last 12 s. A peer that announces no `mc` is never confirmed.
- `[diag] backbone broadcasts=… multicast=… unicast_copies=… probes=…` counts
  datagrams since start.
- Test hook `--zloe-test-mcast-block-file <path>`: while the file exists, datagrams
  arriving on the group are dropped.

Bench (coordinator and satellite, `enp4s0f0`, IPv6 link-local):

- Both sides confirmed multicast within 2 s of meeting; broadcasts went out as one
  multicast datagram with no unicast copies.
- Satellite multicast blocked at 15:51:08: the coordinator switched it to unicast
  copies at 15:51:23 (15 s). Unblocked at 15:51:48: back to multicast at 15:51:58
  (10 s). The satellite stayed a cost-1 neighbour throughout.
- Detection takes 12–17 s (12 s window plus up to one 5 s probe tick), not the
  ≤ 10 s M4 aimed at; still well inside the 45 s neighbour ageing. Broadcasts sent in
  that gap reach the peer only through Zigbee's own retries.

## IPv4 multicast

- Each node joins both groups when it can: IPv6 needs the dual-stack socket, IPv4
  needs an IPv4 address on `--zloe-interface`. It announces each group it joined.
- Each group is probed separately; a peer is reached through its first confirmed group
  in preference order: IPv6 then IPv4, or IPv4 then IPv6 with `--zloe-ipv4`.
- Bench (`--zloe-ipv4` on both nodes): both groups joined and confirmed within 10 s,
  broadcasts went to `239.255.124.18:19789`, unicast addresses unaffected.
- Test hooks: `--zloe-test-mcast-block-file` blocks both groups while the file is
  empty, or one group when it contains `v4` or `v6`; `--zloe-test-ipv4-only` behaves
  like a host without IPv6.
- Per-family failover (both nodes `--zloe-ipv4`, IPv4 blocked on the satellite): the
  satellite's IPv4 group went unconfirmed, the coordinator kept reaching it through
  the IPv6 group (no unicast copies), IPv4 came back after unblocking.
- IPv4-only satellite: bootstrap over IPv4, announces only `mc4`, the dual-stack
  coordinator reaches it through the IPv4 group with no unicast copies, neighbour
  cost 1/1. IPv6 groups are ignored without IPv6.

## Probe overhead

- Every node used to probe every announced group (IPv6 and IPv4) every 5 s. With 3
  backbone nodes that was 144 probes (plus ~2 acks each) per 120 s against 38 data
  datagrams saved.
- Now a node probes each peer's preferred group only, and the other group only while
  the preferred one is absent or unconfirmed: 72 probes per 120 s on the same bench,
  still 1.00 data datagram per broadcast.
- Failover to the other group now takes one more probe interval: IPv6 blocked, the
  peer got unicast copies after 13 s and was back on multicast via IPv4 5 s later.
- At this traffic level (~0.1 broadcasts/s per node) probes plus acks still outweigh
  the saving; piggybacking the ack request on real broadcasts would remove most of it.

## Behaviour

```
Backbone (ziggurat-phy-trel)
    send_broadcast
        Every known peer has acknowledged a recent multicast probe
            - sends one datagram to the network's multicast group
            - sends no unicast copies
        A peer has missed two probes, node is a satellite
            - sends the multicast datagram
            - sends one acked datagram to the coordinator with the forward flag and the same packet number
        A peer has missed two probes, node is the coordinator
            - sends the multicast datagram
            - sends one acked datagram to each unconfirmed peer with the same packet number
        Multicast unavailable (no known interface, IPv4-only link)
            - satellite sends one acked datagram to the coordinator with the forward flag
            - coordinator sends one acked datagram to each peer
        Coordinator does not acknowledge
            - sends one acked datagram to every known peer
            - lowers the coordinator's backbone link quality
        Frame is not an 802.15.4 data frame
            - sends nothing over the backbone
        Node has no network identity yet
            - sends nothing over the backbone
    announce
        Backbone interface known, IPv6 available, multicast port set
            - joins the network's group on that interface
            - announces TXT mc=[group]:port
        Interface unknown, no IPv6, or multicast port 0
            - joins no group
            - announces no mc
        Network (extended PAN ID) changes
            - leaves the old group and joins the new one
            - announces the new mc
    resolve_peer
        Peer announces a multicast address
            - stores it scoped to our backbone interface
        Peer announces none, or an address that is not multicast
            - stores none; the peer is reached by unicast only
        Peer's record is removed
            - clears the stored multicast address
        Record resolved before this node has an identity
            - is applied when the identity becomes known
    receive_multicast
        Datagram from another node on our extended PAN ID
            - delivers the frame to the stack once, 802.15.4 source unchanged
            - stores the datagram's source as the sender's unicast address
            - sends a unicast ack when the ack-request flag is set
        Datagram sent by this node (loopback)
            - drops it
        Packet number already received from that sender
            - drops it
        Different extended PAN ID
            - drops it
    forward (coordinator)
        Broadcast with the forward flag from a satellite
            - acknowledges the satellite
            - delivers the frame to the local stack once
            - sends it unchanged with the forwarded flag to every other peer, acked per hop
        Same sender and packet number seen before
            - acknowledges, forwards nothing
        Datagram already flagged forwarded
            - does not forward it
        Unicast with the forward flag whose 802.15.4 destination is a known peer
            - sends it with the forwarded flag to that peer only
        Unicast with the forward flag for an unknown destination
            - acknowledges, forwards nothing
    receive_forwarded
        Datagram flagged forwarded
            - delivers the frame to the stack once, 802.15.4 source unchanged
            - leaves the original sender's stored address unchanged
            - acknowledges the coordinator
    send_unicast
        Peer acknowledges directly
            - returns Acked, sends nothing to the coordinator
        Peer does not acknowledge directly, node is a satellite
            - sends the frame to the coordinator with the forward flag
            - returns Acked when the coordinator acknowledges
        Neither path acknowledges
            - falls back to the radio
    probe
        Probe interval elapsed
            - sets the ack-request flag on the next multicast datagram
            - sends an empty probe when no broadcast was due within the interval
        Peer acknowledges a probe
            - marks multicast to that peer confirmed
        Peer misses two consecutive probes
            - marks multicast to that peer unconfirmed
            - logs the transition once

Optional suppression
    Backbone
        send_broadcast
            NWK data broadcast that arrived from the backbone within the delivery time
                - transmits on radio only
            NWK command broadcast
                - is sent to the backbone as any other broadcast
    Neighbors
        expected_broadcast_relayers
            Neighbour is a backbone peer
                - is not part of the passive-ack audience
            Neighbour is radio-only
                - is part of the audience as today
```

## Verification on the bench

- Count datagrams per flooded broadcast (device announce from a ZBOSS router) in each
  transport with 2 and 3 backbone nodes.
- Block multicast between the two bench nodes and check the switch to the fallback
  within 10 s and back after unblocking.
- Stop the coordinator for 60 s with two satellites and check that they stay
  neighbours.
- Re-run the deny experiment (On/Off through the satellite) in each transport.

# Secure ZLOE over QUIC: design and gap analysis

Status: design (2026-11-10). Nothing built yet.

Styleguide: as above (`.pre-commit-config.yaml`: `cargo fmt`, clippy with
`-D warnings -Dclippy::all -Dclippy::nursery`). New code lives in
`crates/ziggurat-phy-trel` (`security` module) with the server flags in
`crates/ziggurat-server`.

## Goal

Today the backbone is trusted: anyone on the LAN can read ZLOE headers, inject frames
and fetch the network key from the coordinator. Goal: authenticated and encrypted
ZLOE, without giving up statelessness (Ziggurat keeps no state between starts) and
without breaking the transports above (unicast, multicast, fallback).

## Trust model

- **Root of trust: the Zigbee network key.** Every ZLOE secret is derived from it
  with HKDF-SHA256, salt = extended PAN ID:
  - `ca_key = HKDF(nwk_key, "zloe ca v1")` → Ed25519 network CA (deterministic, so
    every member can recompute it and nothing is stored),
  - `mc_key = HKDF(nwk_key, "zloe multicast v1")` → ChaCha20-Poly1305 group key.
- **Authorization = network membership.** A node that holds the network key is a
  backbone member, as it already is for Zigbee itself. Roles (coordinator / satellite)
  are claims inside the node's certificate, signed by the network CA.
- **Revocation = network key rotation** (ZHA can rotate the network key): new key, new
  CA, every old certificate stops verifying.
- **Enrollment** gives a new satellite the network key. It is the only step that needs
  a secret from outside: a one-time enrollment code.

## Protocol

1. **Node identity.** At start a member generates an ephemeral Ed25519 key pair and
   issues itself a certificate from the derived CA: subject = its EUI64, extension =
   role and NWK address, validity = start time ± 1 year (clocks on MCUs are not
   trusted; validity is not what revocation relies on).
2. **Peer links.** One QUIC connection (quinn + rustls, ALPN `zloe/1`) per peer pair:
   mutual TLS, both certificates must chain to the network CA and name the EUI64 the
   peer announces over mDNS. The lower EUI64 dials, the higher accepts, so a pair has
   one connection.
3. **Frames over QUIC.** 802.15.4 frames travel as QUIC DATAGRAM frames (RFC 9221):
   unreliable, no head-of-line blocking. ZLOE keeps its own per-frame ack (50 ms ×3),
   carried as a datagram too.
4. **Link health from QUIC.** RTT and loss from the QUIC connection replace the
   ack-success estimate; keepalive PINGs replace the multicast probe for unicast peers.
5. **Multicast.** Datagrams to the groups are sealed with `mc_key`
   (ChaCha20-Poly1305, nonce = sender EUI64 ‖ 32-bit packet number, header as AAD).
   Each sender also has a random 32-bit **epoch** per start, sent to every peer over
   its QUIC connection; receivers accept multicast only for a sender's current epoch
   and reject packet numbers already seen in it (replay window). The ZLOE header
   gains the epoch field.
6. **Enrollment.** `ziggurat --zloe-satellite --zloe-enroll <code>`:
   - The coordinator prints a fresh code when asked (`zloe-ctl enroll`, later a ZHA
     button): 128 random bits, base32, valid 10 minutes, one use.
   - The satellite opens QUIC to the coordinator with ALPN `zloe-enroll/1`, accepting
     any server certificate.
   - Both sides compute `proof = HMAC(code, TLS exporter("zloe enroll", 32) ‖ role)`
     and exchange proofs on a stream; each verifies the other's. A man in the middle
     has two different TLS sessions and no code, so it cannot produce either proof;
     with 128 bits it cannot brute-force the code from what it observes.
   - On success the coordinator sends the network settings (the `NetworkInfoPayload`
     the unauthenticated bootstrap sends today) and the connection closes.
7. **Modes.** `--zloe-security none|quic` (default `none` in the spike, so today's
   behaviour stays available). Nodes announce their mode in mDNS TXT `sec`; a `quic`
   node ignores `none` peers.

## Gap analysis

| ID | Gap | Severity | Resolution |
|---|---|---|---|
| Q1 | Microcontroller satellites: spinel2quic measured ~37 KB heap and ~641 ms per QUIC handshake on an ESP32 (ngtcp2). A full mesh means N−1 connections per node. | must for MCU satellites | Host satellites first. For MCUs: connect only to the coordinator plus peers it exchanges unicast with (lazy connections, closed when idle). |
| Q2 | quinn's default loss recovery stretches outages: PTO backoff turned a 3 s outage into a 5.4 s stall (spinel2quic). | must | Fixed congestion window, short max ack delay, 10 ms keepalive datagrams while traffic flows, as tuned in spinel2quic. |
| Q3 | Statelessness: the CA and multicast key are derived from the network key, so a leaked network key gives full backbone access. | accepted | Same trust as Zigbee itself (the network key already decrypts all NWK traffic). Rotation revokes everything. |
| Q4 | Network key rotation: nodes must re-derive keys and reconnect; peers on the old key stop verifying. | must | Rebuild identity and reconnect on `set_extended_pan_id`/network key change; old connections closed; rotation window where both keys are accepted (Zigbee keeps the previous key sequence too). |
| Q5 | Certificate validity needs time: MCUs boot with no clock. | minor | Long validity, time checks disabled in the verifier; certificates are ephemeral and re-issued every start. |
| Q6 | Group key for multicast lets any member forge another member's multicast. | accepted | Same as Zigbee NWK security (any key holder can forge NWK frames). Per-sender keys over QUIC are the upgrade if needed. |
| Q7 | Multicast replay after a sender restart: packet numbers restart randomly. | must | Per-start epoch announced over the authenticated QUIC link; receivers drop unknown epochs. |
| Q8 | Multicast from a sender we have no QUIC connection to yet (startup race) is dropped. | minor | Zigbee retries; the first Link Status round after the connection is up repairs it. |
| Q9 | Enrollment code UX: ZHA has no UI for it. | open | Spike: printed by the coordinator (`zloe-ctl enroll`). Later: ZHA repair/config flow, or a QR code. |
| Q10 | Enrollment code brute force. | covered | 128-bit codes, one use, 10 minute lifetime; proofs bound to the TLS session. A human-typeable short code would need a PAKE (SPAKE2) instead of HMAC. |
| Q11 | mDNS stays unauthenticated: an attacker can announce fake peers or addresses. | covered | Announcements only trigger connection attempts; a peer is accepted only after mutual TLS. Bad addresses cost retries (address rotation exists). |
| Q12 | Mixed networks (some nodes `none`, some `quic`). | minor | `quic` nodes ignore `none` peers; the coordinator decides which mode the network uses and satellites follow its TXT `sec`. |
| Q13 | Datagram size: 802.15.4 frame ≤127 B + ZLOE header + QUIC/UDP/IPv6 overhead. | covered | Well under the 1200 B minimum QUIC path MTU. |
| Q14 | Dependencies (quinn, rustls, ring/aws-lc, rcgen) for the host build; the `no_std` crates are untouched. | minor | Feature-gated in `ziggurat-phy-trel` and `ziggurat-server`. |
| Q15 | The unauthenticated bootstrap (`NETINFO_REQ`) still hands out the network key in `none` mode. | accepted | `quic` mode disables it; enrollment replaces it. |

## Behaviour

```
Security (ziggurat-phy-trel::security)
    derive_keys
        Network key and extended PAN ID known
            - derives the same CA key and multicast key on every node
            - derives different keys for a different network key or extended PAN ID
    issue_identity
        Network keys derived
            - creates a certificate for this node's EUI64 signed by the network CA
            - includes role and NWK address
Backbone (QUIC mode)
    connect_peer
        Peer announced over mDNS with sec=quic, lower EUI64 is us
            - dials the peer with ALPN zloe/1 and our certificate
        Peer's certificate chains to the network CA and names the announced EUI64
            - accepts the connection
            - exchanges multicast epochs
        Peer's certificate is signed by another CA (other network key)
            - closes the connection
            - logs the rejection once
        Peer's certificate names a different EUI64 than announced
            - closes the connection
        Peer announces sec=none
            - does not connect
    send_unicast
        Peer connected
            - sends the frame as a QUIC datagram
            - returns Acked when the ZLOE ack datagram arrives
        No ack after 3 tries
            - falls back to the radio
        Peer not connected
            - falls back to the radio
    send_broadcast
        Peers reachable by multicast
            - sends one datagram per group, sealed with the multicast key
        Other peers
            - sends a QUIC datagram copy to each
    receive_multicast
        Sealed with the multicast key, sender's current epoch, new packet number
            - delivers the frame once
        Fails authentication
            - drops it
        Unknown epoch for that sender
            - drops it
        Packet number already seen in the epoch
            - drops it
    rotate_network_key
        Network key changes
            - derives new keys and certificates
            - closes connections made with the old identity
            - reconnects to peers
Enrollment
    coordinator issue_code
        Requested by zloe-ctl enroll
            - returns a 128-bit base32 code valid 10 minutes
    satellite enroll
        Correct code
            - both proofs verify
            - receives the network settings
            - starts in router role in quic mode
        Wrong code
            - proofs fail on both sides
            - receives nothing
            - coordinator logs the failed attempt
        Code expired or already used
            - coordinator rejects the proof
        Man in the middle without the code
            - neither side's proof verifies
```

## Spike plan

1. Key derivation + self-issued certificates (rcgen), verifier pinned to the derived
   CA.
2. QUIC peer links (quinn) carrying datagrams, with the spinel2quic tuning; ZLOE ack
   over datagrams; fall back to the radio when not connected.
3. Sealed multicast with epochs.
4. Enrollment with code and exporter-bound proofs; `none` mode bootstrap disabled
   in `quic` mode.
5. Bench: the deny run, satellite bootstrap via enrollment, a rogue node with another
   network key rejected, multicast replay rejected, coordinator restart.
