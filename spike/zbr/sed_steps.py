"""SPIKE: client.py for sleepy devices. Each step is sent with ack requested and waits up to
WAIT s for the device's response; a nack is retried up to TRIES times (the client-side answer to
a frame that expired in the parent). Multicast frames are printed as they arrive.

usage: sed_steps.py <device addr> <group> <name:ep/cluster/profile/zclhex> ...
"""
import os, select, socket, struct, sys, time

PORT, WAIT, TRIES = 23106, 30.0, 4
DEV, GROUP = sys.argv[1], sys.argv[2]
STATUS = {1: "malformed", 2: "unknown-device", 3: "policy-denied", 4: "not-our-prefix",
          5: "send-rejected", 6: "delivery-failed", 7: "aps-ack-timeout"}

uc = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
uc.connect((DEV, PORT))
mc = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
mc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
mc.bind((GROUP, PORT))
mreq = socket.inet_pton(socket.AF_INET6, GROUP) + struct.pack("@I", socket.if_nametoindex(os.environ.get("MC_IF", "zbr0")))
mc.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
t_start = time.monotonic()
seq = 0
failed = 0


def stamp():
    return f"[{time.monotonic() - t_start:7.2f}]"


def show_mc(data, src):
    flags, s, ep, cluster, profile, status = struct.unpack("<BBBHHB", data[:8])
    print(f"{stamp()} MULTICAST from {src[0]} ep={ep} cluster=0x{cluster:04x} zcl={data[8:].hex(' ')}", flush=True)


def wait(seconds):
    end = time.monotonic() + seconds
    while (left := end - time.monotonic()) > 0:
        r, _, _ = select.select([mc], [], [], left)
        if r:
            show_mc(*mc.recvfrom(2048))


for step in sys.argv[3:]:
    name, _, arg = step.partition(":")
    if name == "wait":
        print(f"{stamp()} -- listening {arg}s", flush=True)
        wait(float(arg))
        continue
    ep, cluster, profile, zcl = arg.split("/")
    done = False
    for attempt in range(1, TRIES + 1):
        seq += 1
        frame = bytearray.fromhex(zcl)
        frame[1 if int(profile, 16) else 0] = seq & 0x7F  # fresh TSN per attempt
        uc.send(struct.pack("<BBBHHB", 0x80, seq, int(ep), int(cluster, 16), int(profile, 16), 0) + frame)
        t0 = time.monotonic()
        print(f"{stamp()} -- {name} attempt {attempt}: seq={seq} zcl={frame.hex()}", flush=True)
        acked = nacked = None
        while time.monotonic() - t0 < WAIT and not done and not nacked:
            r, _, _ = select.select([uc, mc], [], [], WAIT - (time.monotonic() - t0))
            for s in r:
                data, src = s.recvfrom(2048)
                if s is mc:
                    show_mc(data, src)
                    continue
                flags, hseq, *_rest, status = struct.unpack("<BBBHHB", data[:8])
                if hseq != seq:
                    continue
                dt = time.monotonic() - t0
                if flags & 0x40:
                    acked = dt
                elif flags & 0x20:
                    nacked = STATUS.get(status, status)
                    print(f"{stamp()}    nack {nacked} after {dt:.2f}s", flush=True)
                else:
                    print(f"{stamp()}    ack {acked:.2f}s, response {dt:.2f}s zcl={data[8:].hex(' ')}", flush=True)
                    done = True
        if done:
            break
    if not done:
        failed += 1
        print(f"{stamp()}    FAILED after {TRIES} attempts", flush=True)
print(f"{stamp()} done, {failed} step(s) failed", flush=True)
