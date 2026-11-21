"""SPIKE: soak the border router. Every INTERVAL s: toggle the light (ack requested), read
On/Off back, expect the multicast report. One JSON line per cycle, a summary at the end.

usage: soak.py <device addr> <group> <seconds> <interval> <out.jsonl>
"""
import json, os, select, socket, struct, sys, time

PORT = 23106
DEV, GROUP, DURATION, INTERVAL, OUT = sys.argv[1], sys.argv[2], float(sys.argv[3]), float(sys.argv[4]), sys.argv[5]
EP, CLUSTER, HA = 10, 0x0006, 0x0104
TIMEOUT = 3.0

uc = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
uc.connect((DEV, PORT))
mc = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
mc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
mc.bind((GROUP, PORT))
mreq = socket.inet_pton(socket.AF_INET6, GROUP) + struct.pack("@I", socket.if_nametoindex(os.environ.get("MC_IF", "zbr0")))
mc.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

seq = 0
tsn = 0


def send(zcl_cmd, payload=b"", global_cmd=False):
    """Send one ZCL frame with ack requested; returns (seq, tsn, t0)."""
    global seq, tsn
    seq = (seq + 1) & 0xFF
    tsn = (tsn + 1) & 0x7F  # client TSNs stay below the gateway's rewrite range: easy to tell apart
    fc = 0x00 if global_cmd else 0x01
    frame = bytes([fc, tsn, zcl_cmd]) + payload
    uc.send(struct.pack("<BBBHHB", 0x80, seq, EP, CLUSTER, HA, 0) + frame)
    return seq, tsn, time.monotonic()


def collect(until, want):
    """Gather datagrams until `until`; `want(kind, hdr, zcl, t)` returns True when done."""
    while (left := until - time.monotonic()) > 0:
        r, _, _ = select.select([uc, mc], [], [], left)
        for s in r:
            data = s.recv(2048)
            flags, hseq, ep, cluster, profile, status = struct.unpack("<BBBHHB", data[:8])
            if want("mc" if s is mc else "uc", (flags, hseq, status), data[8:], time.monotonic()):
                return True
    return False


def ms(t, t0):
    return None if t is None else round((t - t0) * 1000, 1)


out = open(OUT, "a")
start = time.monotonic()
state = 0
cycle = 0
while time.monotonic() - start < DURATION:
    cycle += 1
    tick = time.monotonic()
    state ^= 1
    rec = {"cycle": cycle, "wall": time.time(), "state": state}

    # Toggle: expect ack, Default Response (cmd 0x0b, status 0), report with the new value
    s, t, t0 = send(0x01 if state else 0x00)
    got = {"ack": None, "nack": None, "rsp": None, "report": None}

    def want_cmd(kind, hdr, zcl, now):
        flags, hseq, status = hdr
        if kind == "uc" and hseq == s:
            if flags & 0x40:
                got["ack"] = now
            elif flags & 0x20:
                got["nack"] = status
            elif len(zcl) >= 5 and zcl[1] == t and zcl[2] == 0x0B and zcl[4] == 0:
                got["rsp"] = now
        elif kind == "mc" and len(zcl) >= 7 and zcl[2] == 0x0A and zcl[3:5] == b"\0\0" and zcl[6] == state:
            got["report"] = got["report"] or now
        return got["nack"] is not None or (got["ack"] and got["rsp"] and got["report"])

    collect(t0 + TIMEOUT, want_cmd)
    rec.update(cmd_ack=ms(got["ack"], t0), cmd_rsp=ms(got["rsp"], t0), report=ms(got["report"], t0), cmd_nack=got["nack"])

    # Read On/Off: expect ack and a Read Attributes Response with the value we set
    s, t, t0 = send(0x00, b"\x00\x00", global_cmd=True)
    rd = {"ack": None, "nack": None, "rsp": None, "value": None}

    def want_read(kind, hdr, zcl, now):
        flags, hseq, status = hdr
        if kind == "uc" and hseq == s:
            if flags & 0x40:
                rd["ack"] = now
            elif flags & 0x20:
                rd["nack"] = status
            elif len(zcl) >= 8 and zcl[1] == t and zcl[2] == 0x01:
                rd["rsp"], rd["value"] = now, zcl[7]
        return rd["nack"] is not None or (rd["ack"] and rd["rsp"])

    collect(t0 + TIMEOUT, want_read)
    rec.update(read_ack=ms(rd["ack"], t0), read_rsp=ms(rd["rsp"], t0), read_value=rd["value"], read_nack=rd["nack"])
    rec["ok"] = bool(rec["cmd_ack"] and rec["cmd_rsp"] and rec["report"] and rec["read_rsp"] and rd["value"] == state)
    out.write(json.dumps(rec) + "\n")
    out.flush()
    collect(tick + INTERVAL, lambda *a: False)  # late stragglers are drained here
