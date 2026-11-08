"""Benign resolver client: 300 DNS A queries over UDP, one every 20 ms."""
import json, random, socket, struct, sys, time
host = sys.argv[1]; assert host == "10.0.0.1"
def query(name, qid):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
ok = fail = 0
for i in range(300):
    qid = random.randrange(65536)
    s.sendto(query("host%d.service.lab" % i, qid), (host, 53))
    try:
        data, _ = s.recvfrom(2048)
        ok += int(data[:2] == struct.pack(">H", qid))
    except OSError:
        fail += 1
    time.sleep(0.02)
print(json.dumps({"workload": "dns_resolver", "ok": ok, "failed": fail}))
sys.exit(0 if ok else 1)
