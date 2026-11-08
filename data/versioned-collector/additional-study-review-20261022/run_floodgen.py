"""Controlled flood-generator precision capture, reusing the TESTED Phase-4 harness
(probe_precision_phase4) choreography + in-kernel-syscall/NIC/tcpdump measurement UNCHANGED.

Instead of a live bot, this runs DETERMINISTIC, tool-generated flood + benign-bulk workloads as
in-guest commands through the harness's existing "benign" path (timeout WINDOW bash -c payload, measured
identically to every other case). flood_gen.c validated the unprivileged SYN(non-blocking connect)/UDP
approach locally; the in-guest workloads here are the Python equivalents run via a base64 pipe (no binary
staging, no nested quotes, no harness change). This yields flood rows directly comparable to the existing
Kaiten-flood / benign-bulk precision rows.

SAFETY (inherited, unchanged): guest intnet-only on sealed malnet; floods hit ONLY the sealed 10.0.x.y
subnet (third octet >=1 so never the Sink 10.0.0.1 or guest 10.0.0.10; SYNs/UDP die at the gateway, never
leave the host); benign bulk hits ONLY the Sink 10.0.0.1; in-kernel count() maps cannot overflow; BASELINE
restore+poweroff between samples; ORIGINAL restore+poweroff at end. No model, no merge, capture only.

Usage: python3 run_floodgen.py                         # freeze (no VM)
       python3 run_floodgen.py --run --attempt <dir> --approval "<verbatim>"
"""
import argparse, base64, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import probe_precision_phase4 as eng   # noqa: E402  (tested harness: freeze/run_campaign/orchestrator/measurement)

W = eng.WINDOW - 3                     # python self-stops a few s before the orchestrator's timeout
SINK = eng.SINK

# ---- deterministic tool workloads (Python; run in-guest via `echo <b64> | base64 -d | python3 -`) ----
SYN_FLOOD = """
import socket,time,random
end=time.time()+%d; n=0
while time.time()<end and n<300000:
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.setblocking(False)
        a="10.0.%%d.%%d"%%(random.randint(1,254),random.randint(2,254))
        try: s.connect_ex((a,65001))
        except OSError: pass
        s.close()
    except OSError: pass
    n+=1
print(n)
""" % W

UDP_FLOOD = """
import socket,time,random
end=time.time()+%d; n=0
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); buf=b"A"*32
while time.time()<end and n<300000:
    a="10.0.%%d.%%d"%%(random.randint(1,254),random.randint(2,254))
    try: s.sendto(buf,(a,65001))
    except OSError: pass
    n+=1
print(n)
""" % W

UDP_SINK_FLOOD = """
import socket,time
end=time.time()+%d; n=0
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); buf=b"A"*32
while time.time()<end and n<300000:
    try: s.sendto(buf,("%s",65003))
    except OSError: pass
    n+=1
print(n)
""" % (W, SINK)

BULK_DL = """
import socket,time
end=time.time()+%d; n=0
while time.time()<end:
    try:
        s=socket.create_connection(("%s",80),2)
        s.sendall(b"GET / HTTP/1.0\\r\\nHost: sink\\r\\n\\r\\n")
        while s.recv(65536): pass
        s.close(); n+=1
    except OSError: time.sleep(0.02)
print(n)
""" % (W, SINK)

BULK_UP = """
import socket,time
end=time.time()+%d; buf=bytes(65536); n=0
while time.time()<end:
    try:
        s=socket.create_connection(("%s",80),2)
        s.sendall(b"POST /u HTTP/1.0\\r\\nContent-Length: 999999999\\r\\n\\r\\n")
        for _ in range(300): s.sendall(buf)
        s.close(); n+=1
    except OSError: time.sleep(0.02)
print(n)
""" % (W, SINK)

# Kaiten-SCANNER-shaped: SYN fan-out to random sealed 10.0.x.y:23 (telnet) -- the exact flow-shape of
# the Kaiten telnet scanner (the flood we captured from live v14), with NO credential attempt, NO login,
# NO payload delivery, NO self-replication. Pure traffic shape for the detector.
SCAN23 = """
import socket,time,random
end=time.time()+%d; n=0
while time.time()<end and n<300000:
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.setblocking(False)
        a="10.0.%%d.%%d"%%(random.randint(1,254),random.randint(2,254))
        try: s.connect_ex((a,23))
        except OSError: pass
        s.close()
    except OSError: pass
    n+=1
print(n)
""" % W

# Kaiten "PAN" TCP-SYN flooder shape: single-dst half-open SYN flood at the Sink (no handshake completed)
SYNSINK = """
import socket,time
end=time.time()+%d; n=0
while time.time()<end and n<300000:
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.setblocking(False)
        try: s.connect_ex(("%s",80))
        except OSError: pass
        s.close()
    except OSError: pass
    n+=1
print(n)
""" % (W, SINK)

# label -> (python source, expected-target class) ; class "flood" = sealed 10.0.x.y, "sink" = Sink only
WORKLOADS = {
    "scan23":   (SCAN23, "flood"),    # Kaiten telnet-scanner shape (port 23 fan-out)
    "synsink":  (SYNSINK, "sink"),    # Kaiten PAN TCP-SYN-flood shape (single-dst)
    "bulkdl":   (BULK_DL, "sink"),    # benign hard-negative control
}

IPRE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def _assert_safe(label, src, cls):
    import ast
    ast.parse(src)                                   # must be valid python
    for m in IPRE.finditer(src):
        ip = m.group(0)
        if cls == "sink":
            assert ip == SINK, "%s references non-Sink IP %s" % (label, ip)
        else:                                        # flood: only the literal template octets 10.0 are present
            assert ip == SINK or m.group(1) == "10" and m.group(2) == "0", "%s bad IP %s" % (label, ip)
    # flood scripts must build dsts only in 10.0.0.0/16 via the template, never the Sink/guest
    if cls == "flood":
        assert '"10.0.%d.%d"' in src and SINK not in src, "%s flood target not sealed-10.0" % label
        assert "randint(1,254)" in src, "%s flood third octet may hit 10.0.0.x" % label


def build_benign():
    out = {}
    for label, (src, cls) in WORKLOADS.items():
        _assert_safe(label, src, cls)
        b64 = base64.b64encode(src.encode()).decode()
        assert re.fullmatch(r"[A-Za-z0-9+/=]+", b64)          # safe as a bare bash word
        out[label] = "echo %s | base64 -d | python3 -" % b64
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--attempt")
    ap.add_argument("--approval")
    a = ap.parse_args()
    if a.run:
        eng.run_campaign(a.attempt, a.approval)
        return
    # freeze: no malware; our deterministic workloads go through the tested benign path + 1 null
    eng.MALWARE_C2 = []
    eng.MALWARE = []
    eng.BENIGN = build_benign()
    attempt = eng.freeze()
    # relabel: these are controlled tool workloads, not malware/benign samples (recorded for the analysis)
    proto = eng.load(attempt / "protocol.json")
    proto["format"] = "floodgen-precision-capture-v1"
    proto["workload_classes"] = {("benign_" + k): v[1] for k, v in WORKLOADS.items()}
    proto["note"] = ("controlled flood_gen-equivalent workloads: floodsyn/floodudp -> sealed 10.0.x.y (die at "
                     "gateway); floodudpsink/bulkdl/bulkup -> Sink only; kind=benign is the harness RUN PATH, "
                     "not a mal/benign label. Floods = malicious-shape; bulk = benign hard-negative.")
    (attempt / "protocol.json").write_text(json.dumps(proto, indent=2))
    print("floodgen_attempt:", attempt)


if __name__ == "__main__":
    main()
