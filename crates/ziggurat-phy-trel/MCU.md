# ZLOE on the MCU: satellites running Ziggurat on the radio chip

Status: design (2026-11-10). Nothing built yet. Part of the zigpy/ziggurat#84 spike.

Styleguide: the repository's (`.pre-commit-config.yaml`: `cargo fmt`, clippy
`-D warnings -Dclippy::all -Dclippy::nursery`, `clang-format` for the C/C++ glue).
Rust for the MCU is `no_std` + `alloc` on the embassy runtime, like
`ziggurat-ot`; C glue follows `firmwares/glue`. Tests stay at spike level: unit tests
for the `no_std` core on the host, bench runs for the firmware.

## Goal

Today a satellite is a host process (`ziggurat --zloe-satellite`) driving an RCP over
USB: the radio sits wherever the host is. Ziggurat already runs on the chip
(`firmwares/esp32-c6`: Ziggurat as a `no_std` staticlib inside OpenThread RCP, its
only outside link the Spinel vendor tunnel over UART). Goal: a satellite that is the
chip, reaching the ZLOE backbone by one of four transports, and a comparison of them.

## Architecture

```
            ziggurat-driver (router role, unchanged)
                          │ RadioPhy
              ┌───────────┴───────────┐
              │  ZloeCore (no_std)     │  peer table, link selection, ack/retry,
              │  wraps OtLinkPhy       │  dedup, LQI from backbone health
              └───────────┬───────────┘  (TrelPhy's logic, without tokio/std)
                          │ BackboneTransport trait
          ┌───────────────┴────────────────┐
   UART relay (Spinel tunnel)          lwIP on the chip (C glue: UDP + ESP mDNS)
   host: thin relay, puts               netif = Wi-Fi (coex) | SPI Ethernet (W5500)
   datagrams on ZLOE                         | esp-hosted (second ESP32 over SPI)
```

- **ZloeCore** is the part of `TrelPhy` that is not I/O: identity, peer table,
  "backbone first, radio on failure", per-frame ack with retries, duplicate drop,
  backbone health → LQI. It moves into a `no_std` crate, and `TrelPhy` on the host is
  rebuilt on top of it, so both sides keep one implementation.
- **BackboneTransport** is what the core needs from below: send a datagram to a peer
  address, deliver received datagrams, report peers found by discovery, report link
  up/down.
- **Wire format** stays ZLOE v2, unauthenticated (`--zloe-security none`). QUIC on the
  MCU (ngtcp2, ~37 KB heap and ~641 ms per handshake on an ESP32) is a later step.
- **Bootstrap:** the satellite fetches the network settings with `NETINFO_REQ` over
  the backbone (as host satellites do), parses `NetworkInfoPayload` (the protocol crate
  is `no_std`) and configures itself in router role. NWK address from the EUI64,
  frame counters seeded from a clock (SNTP on lwIP transports; the host's time via the
  relay).

## The four transports

| | UART relay | Wi-Fi (coexistence) | SPI Ethernet | esp-hosted |
|---|---|---|---|---|
| Hardware | none extra | none extra | W5500 (or DM9051) module on SPI | second ESP32 (Wi-Fi) on SPI |
| Network stack | host's | lwIP on the C6 | lwIP on the C6 | lwIP on the C6, Wi-Fi on the slave |
| Radio sharing | none | 802.15.4 and Wi-Fi time-slice one radio | none | none (separate chip) |
| Multicast | host's | unreliable on Wi-Fi: announce none | yes | Wi-Fi: announce none |
| Standalone | no (needs a host) | yes | yes | yes |
| What it tests | on-chip router role | coexistence cost | wired standalone | Wi-Fi without coexistence |

## Phases

1. **ZloeCore extraction** (host-tested): move the logic out of `TrelPhy` into a
   `no_std` crate with the transport behind a trait; `TrelPhy` uses it, the existing
   loopback and QUIC tests stay green.
2. **UART relay:** a Spinel vendor command pair carries ZLOE datagrams between the
   chip and the host; the host relay is `ziggurat-phy-trel` in "relay" mode (mDNS and
   UDP on behalf of the chip, no Zigbee stack). Firmware: ZloeCore around `OtLinkPhy`
   in `ziggurat-ot`.
3. **lwIP glue:** C glue for UDP sockets, ESP mDNS (`_zloe._udp` announce and browse),
   SNTP; Rust FFI behind `BackboneTransport`. Brought up on the transport with the
   least risk first: SPI Ethernet if a module is available, otherwise Wi-Fi.
4. **Wi-Fi coexistence:** `CONFIG_ESP_COEX_SW_COEXIST_ENABLE`, coexistence priority
   to 802.15.4, Wi-Fi power save off. Credentials in a gitignored local header the
   user writes.
5. **esp-hosted:** esp-hosted-mcu host component on the C6 over SPI, slave firmware on
   the second ESP32.
6. **Bench comparison:** the deny experiment (On/Off to a device only the MCU
   satellite hears) and a soak per transport; record delivery, latency, Zigbee frame
   loss on the MCU satellite's radio, Wi-Fi throughput where relevant.

## Gap analysis

| ID | Gap | Severity | Resolution |
|---|---|---|---|
| G1 | RAM: OT RCP + Ziggurat + lwIP (+ Wi-Fi driver ~100 KB) in the C6's 512 KB SRAM. | must | Measure free heap per phase; Wi-Fi and esp-hosted builds drop OT features the RCP does not need; neighbour/route tables capped on the MCU. |
| G2 | Coexistence: 802.15.4 loses airtime whenever Wi-Fi holds the radio; Zigbee frames from end devices and routers are missed. | must (measure) | Coexistence priority to 802.15.4, power save off, measure frame loss against the Ethernet build. The result decides whether Wi-Fi coexistence is viable at all. |
| G3 | ESP-IDF Wi-Fi defaults to modem sleep, which delays downlink by up to a DTIM interval (spinel2quic measurement). | must | `WIFI_PS_NONE`. |
| G4 | Timing: Zigbee MAC ACKs come from the radio; ZLOE acks (50 ms × 3) run on the MCU executor next to the stack. | minor | Same constants as the host; measure retry rates. |
| G5 | The UART relay adds Spinel framing and host scheduling to every backbone frame. | minor | Latency comparison in phase 6; acceptable for a test transport. |
| G6 | Clock for frame-counter seeding: the MCU has no wall clock at boot. | must | SNTP on lwIP transports before configuring; the relay passes the host time; otherwise the satellite refuses to start rather than reuse counters. |
| G7 | mDNS on the MCU: ESP mDNS component, one interface, IPv4 and IPv6 link-local. | minor | Announce `xa`, `xp`, `nwk`, `role=router`, `sec=none`, no `mc` on Wi-Fi. |
| G8 | Settings fetched with unauthenticated `NETINFO_REQ` (network key in clear on the LAN). | accepted | Same as host satellites in `none` mode; QUIC enrollment on the MCU later. |
| G9 | esp-hosted on the C6 as host: SDIO is slave-only on the C6, so the link to the second ESP32 is SPI (or UART). | must | SPI transport; check esp-hosted-mcu support for an ESP32-C6 host. |
| G10 | SPI Ethernet needs a module (W5500/DM9051) and wiring. | hardware | Confirm availability; pins from the devkit's free GPIOs. |
| G11 | Firmware OTA/updates and partition size (RCP + Ziggurat + lwIP + Wi-Fi). | minor | 4 MB flash is enough for one app partition; no OTA in the spike. |
| G12 | Host relay must not become a second Zigbee stack. | minor | Relay only moves datagrams and runs discovery; all ZLOE decisions stay in ZloeCore on the chip. |

## Behaviour

```
ZloeCore
    transmit
        Broadcast frame
            - transmits it on the radio
            - sends one backbone datagram per peer (or per announced multicast group)
        Unicast to a backbone peer
            - sends it as a backbone datagram requesting an ack
            - returns Acked when the ack arrives
        No ack after three tries
            - transmits it on the radio
            - lowers the peer's backbone health
        Unicast to an unknown destination
            - transmits it on the radio
    receive
        Datagram from a peer on our extended PAN ID
            - delivers the frame to the stack once, LQI from the peer's backbone health
            - acks it when asked
        Radio frame from a live backbone peer
            - drops it
        Datagram from another network
            - drops it
    bootstrap
        Coordinator found by discovery
            - requests the network settings
            - configures the stack in router role
            - announces itself with Device_annce
        Clock unknown
            - does not start
UART relay (host)
    forward_up
        Datagram from the backbone for the chip
            - passes it to the chip over the Spinel tunnel unchanged
    forward_down
        Datagram from the chip with a destination
            - sends it on the backbone from the relay's socket
    discovery
        Peer found by mDNS
            - reports it to the chip
lwIP transport (C glue)
    start
        Network interface up (Wi-Fi, Ethernet or esp-hosted)
            - opens the UDP socket
            - announces _zloe._udp with xa, xp, nwk, role, sec
            - browses for peers and reports them
        Network interface down
            - reports link down
            - ZloeCore sends everything on the radio
```

## Hardware needed

- New ESP32-C6 (in hand): UART relay and Wi-Fi coexistence.
- SPI Ethernet module (W5500 or DM9051) with jumper wires: SPI Ethernet.
- Second ESP32 with Wi-Fi, wired to the C6 over SPI: esp-hosted.
