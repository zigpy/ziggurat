"""SPIKE: probe a sleepy end device through the border router. Sends a Read Attributes
(On/Off) with ack requested every INTERVAL s for DURATION s, listens throughout, then prints
each request's fate: gateway ack/nack (and when) and whether/when the response came back.

usage: sleepy_probe.py <device addr> <duration> <interval>
"""
import select, socket, struct, sys, time

PORT = 23106
DEV, DURATION, INTERVAL = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
STATUS = {1: "malformed", 2: "unknown-device", 3: "policy-denied", 4: "not-our-prefix",
          5: "send-rejected", 6: "delivery-failed", 7: "aps-ack-timeout"}

uc = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
uc.connect((DEV, PORT))
sent = {}  # seq -> {t0, tsn, ack, nack, rsp}
start = time.monotonic()
next_send = start
seq = 0
while True:
    now = time.monotonic()
    if now >= next_send and now - start < DURATION:
        seq += 1
        frame = bytes([0x00, seq & 0x7F, 0x00, 0x00, 0x00])
        uc.send(struct.pack("<BBBHHB", 0x80, seq, 10, 0x0006, 0x0104, 0) + frame)
        sent[seq] = {"t0": now, "tsn": seq & 0x7F, "ack": None, "nack": None, "rsp": None}
        next_send += INTERVAL
    if now - start > DURATION + 35:  # past the gateway's 30 s pending TTL
        break
    r, _, _ = select.select([uc], [], [], 0.05)
    if r:
        data = uc.recv(2048)
        flags, hseq, ep, cluster, profile, status = struct.unpack("<BBBHHB", data[:8])
        e = sent.get(hseq)
        if e is None:
            continue
        t = round(time.monotonic() - e["t0"], 2)
        if flags & 0x40:
            e["ack"] = t
        elif flags & 0x20:
            e["nack"] = (t, STATUS.get(status, status))
        elif data[8:] and data[9] == e["tsn"]:
            e["rsp"] = t

print("seq  sent_at  ack_s  nack                     response_s")
for s, e in sent.items():
    print(f"{s:3}  {e['t0'] - start:7.1f}  {e['ack'] if e['ack'] is not None else '-':>5}  "
          f"{str(e['nack']) if e['nack'] else '-':24} {e['rsp'] if e['rsp'] is not None else '-'}")
ok = sum(e["rsp"] is not None for e in sent.values())
print(f"responses {ok}/{len(sent)}; acked {sum(e['ack'] is not None for e in sent.values())}; "
      f"nacked {sum(e['nack'] is not None for e in sent.values())}")
