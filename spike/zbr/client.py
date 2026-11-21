"""SPIKE: talk raw ZCL to a Zigbee device over UDP/IPv6 through the border router."""
import socket, struct, sys, time, select

PORT = 23106
DEV = sys.argv[1]                       # device IPv6 address
GROUP = sys.argv[2]                     # multicast group
steps = sys.argv[3:]

FLAGS = {0x80: "ack-req", 0x40: "ack", 0x20: "nack", 0x08: "unsolicited"}
STATUS = {1: "malformed", 2: "unknown-device", 3: "policy-denied", 4: "not-our-prefix",
          5: "send-rejected", 6: "delivery-failed", 7: "aps-ack-timeout"}

def hdr(flags, seq, ep, cluster, profile=0):
    return struct.pack("<BBBHHB", flags, seq, ep, cluster, profile, 0)

def show(tag, data, src):
    flags, seq, ep, cluster, profile, status = struct.unpack("<BBBHHB", data[:8])
    names = ",".join(n for b, n in FLAGS.items() if flags & b) or "-"
    st = f" status={STATUS.get(status, status)}" if status else ""
    print(f"{tag} from [{src[0]}]:{src[1]} flags={names} seq={seq} ep={ep} cluster=0x{cluster:04x} "
          f"profile=0x{profile:04x}{st} zcl={data[8:].hex(' ') or '-'}", flush=True)

uc = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
uc.connect((DEV, PORT))
mc = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
mc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
mc.bind((GROUP, PORT))
mreq = socket.inet_pton(socket.AF_INET6, GROUP) + struct.pack("@I", socket.if_nametoindex(__import__("os").environ.get("MC_IF", "zbr0")))
mc.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

def drain(seconds):
    end = time.time() + seconds
    while (left := end - time.time()) > 0:
        r, _, _ = select.select([uc, mc], [], [], left)
        for s in r:
            data, src = s.recvfrom(2048)
            show("UNICAST  " if s is uc else "MULTICAST", data, src)

for i, step in enumerate(steps, 1):
    kind, _, arg = step.partition(":")
    if kind == "wait":
        print(f"-- listening {arg}s", flush=True); drain(float(arg)); continue
    ep, cluster, profile, zcl = arg.split("/")
    pkt = hdr(0x80, i, int(ep), int(cluster, 16), int(profile, 16)) + bytes.fromhex(zcl)
    print(f"-- {kind}: send seq={i} ep={ep} cluster={cluster} zcl={zcl}", flush=True)
    uc.send(pkt); drain(3)
