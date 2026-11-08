"""Per-TCP-connection TLS progress in the E5 HTTPS captures (port 443): how far each handshake got and who
closed it. Reads each pcap with tshark; prints one summary line per run."""
import collections, glob, subprocess, sys
from pathlib import Path
SINK = "10.0.0.1"
A = Path(sys.argv[1])
for p in sorted(glob.glob(str(A / "runs" / "*-https.zip" / "output" / "run_*" / "packet_capture.pcap"))):
    name = Path(p).parts[-4][:-4]
    out = subprocess.run(["tshark", "-r", p, "-Y", "tcp.port==443", "-T", "fields", "-E", "separator=|",
                          "-e", "tcp.stream", "-e", "ip.src", "-e", "tcp.flags.syn", "-e", "tcp.flags.ack",
                          "-e", "tcp.flags.reset", "-e", "tcp.flags.fin", "-e", "tls.handshake.type",
                          "-e", "tls.record.content_type", "-e", "tcp.len", "-e", "tls.record.opaque_type"],
                         capture_output=True, text=True).stdout.splitlines()
    s = collections.defaultdict(lambda: {"ch": 0, "sh": 0, "srv_data": 0, "cli_data": 0, "srv_rst": 0, "cli_rst": 0,
                                         "srv_fin": 0, "cli_fin": 0, "synack": 0, "srv_bytes": 0})
    for line in out:
        st, src, syn, ack, rst, fin, hs, ct, tlen, ot = (line.split("|") + [""] * 10)[:10]
        T = lambda v: v in ("1", "True")
        d = s[st]; srv = src == SINK
        if T(syn) and T(ack): d["synack"] += 1
        if "1" in hs.split(","): d["ch"] += 1
        if "2" in hs.split(","): d["sh"] += 1
        if "23" in ct.split(",") or "23" in ot.split(","): d["srv_data" if srv else "cli_data"] += 1
        if T(rst): d["srv_rst" if srv else "cli_rst"] += 1
        if T(fin): d["srv_fin" if srv else "cli_fin"] += 1
        if srv and tlen: d["srv_bytes"] += int(tlen)
    n = len(s)
    c = lambda k, pred=lambda v: v > 0: sum(1 for d in s.values() if pred(d[k]))
    print("%-20s conns=%4d synack=%4d clientHello=%4d serverHello=%4d serverAppData=%4d clientAppData=%4d | server RST=%4d server FIN=%4d | client RST=%3d FIN=%3d | conns where server sent 0 bytes=%d" % (
        name, n, c("synack"), c("ch"), c("sh"), c("srv_data"), c("cli_data"), c("srv_rst"), c("srv_fin"),
        c("cli_rst"), c("cli_fin"), sum(1 for d in s.values() if d["srv_bytes"] == 0)))
