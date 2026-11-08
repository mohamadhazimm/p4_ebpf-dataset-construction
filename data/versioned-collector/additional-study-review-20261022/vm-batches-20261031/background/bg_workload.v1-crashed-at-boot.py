"""Benign background workload, started at boot by the guest user's @reboot crontab entry, outside the
monitored process tree. It runs until the VM powers off: every 0.5 s an HTTP GET to the Sink, every 2 s a
DNS query to the Sink, and every second a line appended to a local log. All traffic goes to the Sink
10.0.0.1 only and is marked (path /bg/..., query names bg*.background.lab) so captures can be checked."""
import json, os, random, socket, struct, sys, time, urllib.request

SINK = "10.0.0.1"
log_path = sys.argv[1]
boot = open("/proc/sys/kernel/random/boot_id").read().strip()[:8]
req = urllib.request.build_opener()
req.addheaders = [("User-Agent", "bg-workload/1")]
dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns.settimeout(0.5)


def dns_query(n):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in ("bg%d" % n, "background", "lab"))
    qid = random.randrange(65536)
    dns.sendto(struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00\x00\x01\x00\x01", (SINK, 53))
    try:
        dns.recvfrom(2048)
    except OSError:
        pass


n = 0
with open(log_path, "a", buffering=1) as log:
    log.write(json.dumps({"event": "start", "boot": boot, "pid": os.getpid(), "t": time.time()}) + "\n")
    while True:
        try:
            with req.open("http://%s/bg/%s/%d" % (SINK, boot, n), timeout=2) as r:
                r.read()
            status = "ok"
        except OSError as e:
            status = type(e).__name__
        if n % 4 == 0:
            dns_query(n)
        if n % 2 == 0:
            log.write(json.dumps({"n": n, "t": time.time(), "http": status}) + "\n")
        n += 1
        time.sleep(0.5)
