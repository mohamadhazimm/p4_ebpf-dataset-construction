#!/usr/bin/env python3
"""Session lab, more varied network-active benign programs (prepared 2026-11-17; run on the user's approval).

Why: in the base dataset (base/20261117b) the network view flags 56-67% of the network-active benign programs. Its
benign side has few programs that use the network, so when one of them is held out, the training data rarely hold a
benign program with the same kind of traffic. This batch adds benign clients that produce the same traffic shapes as
the existing ones -- periodic polling, kept-alive sessions, downloads, uploads, TLS handshakes, mail and FTP sessions,
DNS -- from several independent programs, so each held-out program still has benign look-alikes in training:

  curl, wget, openssl, telnet   the dataset's own network builds (all three modes), new tasks: SMTP, POP3, FTP and
                                their TLS forms against the Sink's INetSim, HTTP(S) to outside names and addresses
                                (the sinkhole hands 80/443/53 to INetSim), a 40-address crawl, polling with waits,
                                uploads, rate-limited downloads from the test server
  webfetch, netpoll             the lab's request tools (as in the pilot, flood and Triage batches): check-ins every
                                2-30 s, browsing, downloads, uploads, a DNS burst, kept-alive and TLS polling
  labtransport (Go)             new program: a static Go client over plain HTTP, TLS 1.2, TLS 1.3 and QUIC (HTTP/3)
  python-client                 new program: a standard-library Python client over plain HTTP, TLS 1.2 and TLS 1.3

Every destination is answered: the Sink's INetSim (21, 25, 80, 110, 443, 465, 990, 995), its dnsmasq (53), outside
addresses on 80/443/53 (the sinkhole redirects them to INetSim), or the transport test server this batch runs on the
Sink (labtransport server on 10.0.0.1: 9080 plain, 9441-9443 TLS 1.1-1.3, 9444/udp QUIC; the encrypted-traffic test's
server, transport21/). No task touches the sinkhole's silent listener. Everything else is the silent-server batch's:
the session-lab phases, Sink capture, strict checks, 4x background, the same sinkhole and DNS redirect. No malware.

Controls: 3 nulls, 3 background-only sessions, and 3 repeats of dataset network tasks with their dataset arguments
("batch_control"; they test that this batch's conditions, including the test server, leave other traffic unchanged,
and are left out of every scoring pool).

Pre-registered analysis: in the protocol ("expectations"), scored by score_netbenign.py.

  /usr/bin/python3 run_session_netbenign.py --self-test
  /usr/bin/python3 run_session_netbenign.py --freeze-only
  /usr/bin/python3 run_session_netbenign.py --run-all --attempt DIR --protocol-sha256 SHA --approval "<user's words>"
"""
import argparse
import hashlib
import json
import random
import re
import secrets
import shutil
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_session_lab as lab   # noqa: E402
import run_session_main as M    # noqa: E402

require, sha256, save, load, now_utc = lab.require, lab.sha256, lab.save, lab.load, lab.now_utc
SEED = 5111
REV5_SAMPLES = lab.REV5
SAMPLES = HERE / "netbenign-samples"
lab.REV5 = SAMPLES                 # every archive lookup of the driver now reads this one folder (as the Triage batch)
T21 = HERE.parent / "transport21"
LABT = T21 / "bin" / "labtransport"
LABT_SHA = "68dfd672e5ff23d27f50d2f0e3c895b83cea6684f2400742bd48db4d7d6cda4c"
PYCLIENT = T21 / "transport_client.py"
LT_ZIP = "labtransport-client.zip"
SINK_LAB = "/home/remnux/hazim-netbenign"
TEST_PORTS = {"http": ("tcp", 9080), "tls11": ("tcp", 9441), "tls12": ("tcp", 9442), "tls13": ("tcp", 9443),
              "quic": ("udp", 9444)}
INETSIM_PORTS = {21, 25, 53, 80, 110, 443, 465, 990, 995}
OUTSIDE_PORTS = {53, 80, 443}           # the sinkhole hands these to INetSim/dnsmasq; anything else is the silent listener
OUTSIDE = re.compile(r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$|\.example$")

DATASET = {   # the dataset's network builds: (program, mode) -> archive (net-a; net-b holds the same binary)
    ("curl", "D"): "amd64_dynamic-training-curl-net-a-7dc07fd7.zip",
    ("curl", "S"): "amd64_static-training-curl-net-a-d912f186.zip",
    ("curl", "I"): "i386_static-training-curl-net-a-ab7a2b71.zip",
    ("wget", "D"): "amd64_dynamic-validation-wget-net-a-08d9d0fa.zip",
    ("wget", "S"): "amd64_static-validation-wget-net-a-0a23aee0.zip",
    ("wget", "I"): "i386_static-validation-wget-net-a-72b6617b.zip",
    ("openssl", "D"): "amd64_dynamic-training-openssl-net-a-216cc93a.zip",
    ("openssl", "S"): "amd64_static-training-openssl-net-a-21ba90cb.zip",
    ("openssl", "I"): "i386_static-training-openssl-net-a-60189b13.zip",
    ("telnet", "S1"): "amd64_static-training-telnet-net-a-58da93ec.zip",
    ("telnet", "S2"): "amd64_static-training-telnet-net-a-adcf3ee0.zip"}
MODE = {"D": "native_amd64_dynamic", "S": "native_amd64_static", "I": "native_i386_static",
        "S1": "native_amd64_static", "S2": "native_amd64_static"}
PROJECT = {"curl": "curl", "wget": "wget", "openssl": "openssl", "telnet": "inetutils"}
MAIL = ["--mail-from", "alerts@lab.example", "--mail-rcpt", "ops@lab.example", "-T", "/etc/os-release"]
CU = ["--noproxy", "*", "-s"]
WG = ["--no-proxy", "-q"]
POLL_NAMES = ["http://status.lab.example/health?i=%d" % i for i in range(1, 8)]
POLL_SINK = ["http://10.0.0.1/ping?i=%d" % i for i in range(1, 16)]

# (program, build, task, argv, destinations as host:port). The lab's dnsmasq answers A and refuses AAAA (it has no
# upstream server), and the guest's resolver passes that on as SERVFAIL; musl then fails the whole lookup (glibc uses
# the A answer). So the name-based tasks run on glibc builds, or ask for IPv4 only where the client passes that to the
# resolver (wget --inet4-only; musl curl sends the AAAA query even with -4). Found in the first attempt
# (runs/20261117T105520781257Z, session n003), which was stopped after 5 sessions and is not used.
TASKS = [
    ("curl", "S", "curl-smtp", CU + ["--max-time", "20"] + MAIL + ["smtp://10.0.0.1/lab.example"], ["10.0.0.1:25"]),
    ("curl", "I", "curl-pop3", CU + ["--max-time", "20", "-u", "lab:lab", "-o", "pop3.out", "pop3://10.0.0.1/"],
     ["10.0.0.1:110"]),
    ("curl", "I", "curl-ftp", CU + ["--max-time", "20", "-o", "ftp.out", "ftp://10.0.0.1/"], ["10.0.0.1:21"]),
    ("curl", "S", "curl-crawl", CU + ["--max-time", "90", "-o", "page#1.html", "http://198.51.100.[10-49]/index.html"],
     ["198.51.100.10:80"]),
    ("curl", "D", "curl-cdn-tls", CU + ["--max-time", "90", "-k", "-o", "asset#1.js",
                                        "https://cdn[1-8].lab-cdn.example/lib.js"], ["cdn1.lab-cdn.example:443"]),
    ("curl", "D", "curl-post", CU + ["--max-time", "20", "-X", "POST", "--data-binary",
                                     "@/usr/share/common-licenses/GPL-3", "-o", "post.out",
                                     "http://telemetry.lab.example/api/v1/report"], ["telemetry.lab.example:80"]),
    ("curl", "S", "curl-ftps", CU + ["--max-time", "20", "-k", "-o", "ftps.out", "ftps://10.0.0.1/"],
     ["10.0.0.1:990"]),
    ("curl", "I", "curl-pop3s", CU + ["--max-time", "20", "-k", "-u", "lab:lab", "-o", "pop3s.out",
                                      "pop3s://10.0.0.1/"], ["10.0.0.1:995"]),
    ("curl", "I", "curl-smtps", CU + ["--max-time", "20", "-k"] + MAIL + ["smtps://10.0.0.1/lab.example"],
     ["10.0.0.1:465"]),
    ("curl", "S", "curl-download", CU + ["--max-time", "60", "--limit-rate", "2M", "-o", "big#1.bin",
                                         "http://10.0.0.1:9080/bytes?n=8000000&part=[1-4]"], ["10.0.0.1:9080"]),
    ("curl", "D", "curl-api-tls", CU + ["--max-time", "60", "-k", "-o", "api#1.json",
                                        "https://api.lab.example/v1/items?page=[1-20]"], ["api.lab.example:443"]),
    ("wget", "S", "wget-poll-names", WG + ["--inet4-only", "--wait=10", "-O", "poll.out"] + POLL_NAMES,
     ["status.lab.example:80"]),
    ("wget", "I", "wget-poll-sink", WG + ["--wait=3", "-O", "poll.out"] + POLL_SINK, ["10.0.0.1:80"]),
    ("wget", "D", "wget-ftp", WG + ["--no-remove-listing", "-O", "ftp.out", "ftp://10.0.0.1/"], ["10.0.0.1:21"]),
    ("wget", "D", "wget-download", WG + ["--limit-rate=400k", "-O", "dl.bin", "http://10.0.0.1:9080/bytes?n=8000000"],
     ["10.0.0.1:9080"]),     # the test server serves at most 8 MiB per request
    ("wget", "S", "wget-post", WG + ["--inet4-only", "--post-file=/usr/share/common-licenses/GPL-3", "-O", "post.out",
                                     "http://api.lab.example/submit"], ["api.lab.example:80"]),
    ("wget", "I", "wget-mirror", WG + ["-r", "-l", "1", "-np", "-P", "mirror", "http://10.0.0.1/"], ["10.0.0.1:80"]),
    ("openssl", "S", "openssl-smtps", ["s_client", "-connect", "10.0.0.1:465", "-servername", "mail.lab.example",
                                       "-brief"], ["10.0.0.1:465"]),
    ("openssl", "D", "openssl-starttls", ["s_client", "-connect", "10.0.0.1:25", "-starttls", "smtp", "-brief"],
     ["10.0.0.1:25"]),
    ("openssl", "I", "openssl-pop3s", ["s_client", "-connect", "10.0.0.1:995", "-brief"], ["10.0.0.1:995"]),
    ("openssl", "S", "openssl-ftps", ["s_client", "-connect", "10.0.0.1:990", "-brief"], ["10.0.0.1:990"]),
    ("openssl", "D", "openssl-reconnect", ["s_client", "-connect", "www.lab.example:443", "-servername",
                                           "www.lab.example", "-reconnect", "-brief"], ["www.lab.example:443"]),
    ("openssl", "I", "openssl-tls13", ["s_client", "-connect", "10.0.0.1:9443", "-tls1_3", "-brief"],
     ["10.0.0.1:9443"]),
    ("telnet", "S1", "telnet-smtp", ["-E", "10.0.0.1", "25"], ["10.0.0.1:25"]),
    ("telnet", "S2", "telnet-pop3", ["-E", "10.0.0.1", "110"], ["10.0.0.1:110"])]

# the transport test's Go client (new program), one archive
LT_TASKS = [("lt-%s-%s" % (mode, work), ["client", mode, work, "10.0.0.1", "-duration", dur])
            for mode, work, dur in (("http", "poll", "60s"), ("tls12", "poll", "60s"), ("tls13", "poll", "60s"),
                                    ("quic", "poll", "60s"), ("tls13", "session", "60s"), ("quic", "session", "60s"),
                                    ("http", "bulk", "20s"), ("tls12", "bulk", "20s"))]
# the transport test's Python client (new program), via webfetch's pyexec (as the flood batch ran the Python tools)
PY_TASKS = [("py-%s-%s" % (mode, work), ["pyexec", "transport_client.py", mode, work, "10.0.0.1", dur])
            for mode, work, dur in (("http", "poll", "60"), ("tls12", "poll", "60"), ("tls13", "session", "60"),
                                    ("http", "session", "60"), ("tls13", "bulk", "20"))]
# the lab's request tools, grouped by traffic shape (the first word of the name) as in the pilot, flood and Triage runs
TOOL_TASKS = [
    ("checkin-5s-public", "webfetch", ["beacon", "16", "203.0.113.81", "80", "5000"], ["203.0.113.81:80"]),
    ("checkin-10s-public", "webfetch", ["beacon", "9", "198.51.100.82", "80", "10000"], ["198.51.100.82:80"]),
    ("checkin-30s-public", "webfetch", ["beacon", "4", "192.0.2.83", "80", "30000"], ["192.0.2.83:80"]),
    ("browse-public-b", "webfetch", ["session", "40", "192.0.2.84", "80"], ["192.0.2.84:80"]),
    ("browse-sink-b", "webfetch", ["session", "120", "10.0.0.1", "80"], ["10.0.0.1:80"]),
    ("download-public-b", "webfetch", ["bulk", "15", "198.51.100.85", "80"], ["198.51.100.85:80"]),
    ("download-sink-b", "webfetch", ["bulk", "60", "10.0.0.1", "80"], ["10.0.0.1:80"]),
    ("upload-sink-small", "webfetch", ["bulkup", "20", "10.0.0.1", "80"], ["10.0.0.1:80"]),
    ("upload-public", "webfetch", ["bulkup", "40", "203.0.113.86", "80"], ["203.0.113.86:80"]),
    ("dns-burst-300", "webfetch", ["dns", "300", "10.0.0.1"], ["10.0.0.1:53"]),
    ("checkin-netpoll-2s", "netpoll", ["poll", "2000", "60000", "10.0.0.1", "80"], ["10.0.0.1:80"]),
    ("checkin-netpoll-tls-5s", "netpoll", ["tlspoll", "5000", "60000", "10.0.0.1", "443"], ["10.0.0.1:443"]),
    ("keepalive-netpoll-3s", "netpoll", ["keepalive", "3000", "60000", "10.0.0.1", "80"], ["10.0.0.1:80"]),
    ("keepalive-netpoll-tls-5s", "netpoll", ["tlskeep", "5000", "60000", "10.0.0.1", "443"], ["10.0.0.1:443"]),
    ("device-netpoll-b", "netpoll", ["device", "b", "60000", "10.0.0.1"], ["10.0.0.1:80"])]
BATCH_CONTROLS = ["amd64_static-training-curl-net-a-d912f186.zip", "i386_static-validation-wget-net-a-72b6617b.zip",
                  "amd64_dynamic-training-openssl-net-a-216cc93a.zip"]


def tool_set():
    """lab.TOOLS plus the Python client, verified against its file hash (staged and installed like the flood batch's
    Python tools: enter.sh installs every *.py into the tool folder; session.sh copies it beside webfetch)."""
    tools = dict(lab.TOOLS)
    tools["transport_client.py"] = (PYCLIENT, sha256(PYCLIENT))
    return tools


def labtransport_zip(path):
    """A plain zip holding the Go client as its one member, with fixed metadata so the bytes are reproducible."""
    data = LABT.read_bytes()
    require(hashlib.sha256(data).hexdigest() == LABT_SHA, "labtransport binary changed")
    info = zipfile.ZipInfo("labtransport", date_time=(2026, 11, 15, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o755 << 16
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(info, data)


def build_samples(folder):
    """Copies of the dataset archives the batch uses (byte-identical) and the Go client's archive."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    names = set(DATASET.values()) | set(BATCH_CONTROLS) | set(M.NULLS)
    for name in sorted(names):
        src, dst = REV5_SAMPLES / name, folder / name
        require(src.is_file(), "dataset archive missing: " + name)
        if not dst.is_file() or sha256(dst) != sha256(src):
            shutil.copyfile(src, dst)
    lt = folder / LT_ZIP
    labtransport_zip(lt)
    return folder


def destinations_ok(dests):
    for d in dests:
        host, port = d.rsplit(":", 1)
        port = int(port)
        if host == lab.SINK_IP:
            if port not in INETSIM_PORTS and port not in {p for _, p in TEST_PORTS.values()}:
                return False
        elif OUTSIDE.search(host):
            if port not in OUTSIDE_PORTS:
                return False
        else:
            return False
    return True


def specs():
    cases = {c["sample"]: c for c in load(M.PAYLOAD / "cases.json")}
    buckets = {}

    def add(key, spec):
        buckets.setdefault(key, []).append(spec)
    for program, build, task, argv, dests in TASKS:
        arc = DATASET[(program, build)]
        require(cases[arc]["program"] == program and cases[arc]["mode"] == MODE[build], "archive mismatch: " + arc)
        add(program, {"kind": "benign", "name": "%s-%s" % (task, arc[-12:-4]), "program": program,
                      "project": PROJECT[program], "mode": MODE[build], "network": True, "source": "archive",
                      "archive": arc, "args": argv, "fixtures": [], "new_task_args": True, "destinations": dests})
    for task, argv in LT_TASKS:
        add("labtransport", {"kind": "benign", "name": task, "program": "labtransport", "project": "labtransport",
                             "mode": "native_amd64_static", "network": True, "source": "archive", "archive": LT_ZIP,
                             "args": argv, "fixtures": [], "new_task_args": True,
                             "destinations": ["10.0.0.1:%d" % TEST_PORTS[argv[1]][1]]})
    for task, argv in PY_TASKS:
        add("python-client", {"kind": "benign", "name": task, "program": "python-client", "project": "python-client",
                              "mode": "native_amd64_dynamic", "network": True, "source": "tool", "tool": "webfetch",
                              "args": argv, "destinations": ["10.0.0.1:%d" % TEST_PORTS[argv[2]][1]]})
    for task, tool, argv, dests in TOOL_TASKS:
        add(tool, {"kind": "benign", "name": task, "program": tool, "network": True, "source": "tool", "tool": tool,
                   "args": argv, "destinations": dests})
    controls = [{"kind": "null", "name": n[:-4], "source": "archive", "archive": n,
                 "args": load(M.PAYLOAD / "arguments" / (n + ".json"))} for n in M.NULLS]
    controls += [{"kind": "none", "name": "background-only"} for _ in range(3)]
    for arc in BATCH_CONTROLS:
        c = cases[arc]
        controls.append({"kind": "benign", "name": "control-%s-%s" % (c["program"], arc[-12:-4]),
                         "program": c["program"], "project": c["project"], "mode": c["mode"], "network": True,
                         "source": "archive", "archive": arc, "args": load(M.PAYLOAD / "arguments" / (arc + ".json")),
                         "fixtures": [], "batch_control": True})
    rng = random.Random(SEED)
    for key in sorted(buckets):
        rng.shuffle(buckets[key])
    rng.shuffle(controls)
    order = sorted(buckets)
    rng.shuffle(order)
    benign = []
    while any(buckets.values()):                    # round-robin over programs: any prefix covers them all
        for key in order:
            if buckets[key]:
                benign.append(buckets[key].pop(0))
    out, ci = [], 0
    step = max(1, len(benign) // len(controls))
    for i, s in enumerate(benign, 1):
        out.append(s)
        if i % step == 0 and ci < len(controls):
            out.append(controls[ci])
            ci += 1
    out += controls[ci:]
    return out


# ------------------------------------------------------------------------------------- the transport test server

def _server_dir(attempt):
    d = Path(attempt) / "phases" / "test-server"
    d.mkdir(parents=True, exist_ok=True)
    return d


def server_listening(module):
    text = lab.sink_run(module, ["/bin/bash", "-c", "ss -Hltnu 2>/dev/null"]).stdout or ""
    return {mode: ("%s:%d" % (lab.SINK_IP, port)) in text for mode, (_, port) in TEST_PORTS.items()}


def server_start(module, attempt):
    d = _server_dir(attempt)
    record = {"phase": "test-server-start", "status": "failed", "started_utc": now_utc(), "binary_sha256": LABT_SHA}
    try:
        r = lab.sink_run(module, ["/bin/bash", "-c", "mkdir -p %s && pkill -x labtransport; echo ok" % SINK_LAB])
        require("ok" in (r.stdout or ""), "Sink lab folder: %s" % (r.stderr or "")[:200])
        cp = lab.sink_copyto(module, LABT, SINK_LAB + "/labtransport")
        require(cp.returncode == 0, "copy to the Sink failed: %s" % (cp.stderr or "")[:200])
        r = lab.sink_run(module, ["/usr/bin/sha256sum", SINK_LAB + "/labtransport"])
        got = (r.stdout or "").split()[0] if (r.stdout or "").strip() else ""
        require(got == LABT_SHA, "server binary hash on the Sink: %s" % got)
        log = "%s/server-%s.log" % (SINK_LAB, Path(attempt).name)
        r = lab.sink_run(module, ["/bin/bash", "-c", "cd %s && chmod 755 labtransport && setsid bash -c 'nohup "
                                  "./labtransport server -addr %s > %s 2>&1 & echo $! > server.pid' && sleep 3 && cat "
                                  "server.pid" % (SINK_LAB, lab.SINK_IP, log)])
        record.update({"server_pid": (r.stdout or "").strip(), "server_log": log})
        record["listening"] = server_listening(module)
        require(all(record["listening"].values()), "test server not listening on every port: %s" % record["listening"])
        record["status"] = "passed"
    finally:
        record["finished_utc"] = now_utc()
        save(d / ("start-%s.json" % lab.stamp()), record)
    return record


def server_stop(module, attempt):
    d = _server_dir(attempt)
    record = {"phase": "test-server-stop", "status": "failed", "started_utc": now_utc()}
    try:
        r = lab.sink_run(module, ["/bin/bash", "-c", "cd %s 2>/dev/null && (kill $(cat server.pid) 2>/dev/null; "
                                  "sleep 1; pkill -x labtransport; true); (pgrep -x labtransport || echo stopped)"
                                  % SINK_LAB])
        record["stopped"] = "stopped" in (r.stdout or "")
        record["listening_after"] = server_listening(module)
        starts = sorted(d.glob("start-*.json"))
        log = load(starts[-1]).get("server_log") if starts else None
        if log:
            cp = lab.sink_copyfrom(module, log, d / "server.log")
            record["log_fetched"] = cp.returncode == 0 and (d / "server.log").is_file()
            if record["log_fetched"]:
                record["log_sha256"] = sha256(d / "server.log")
        require(record["stopped"] and not any(record["listening_after"].values()),
                "test server still running: %s" % record["listening_after"])
        record["status"] = "passed"
    finally:
        record["finished_utc"] = now_utc()
        save(d / ("stop-%s.json" % lab.stamp()), record)
    return record


ORIGINAL_PREPARE, ORIGINAL_RESTORE = lab.sink_prepare, lab.sink_restore


def sink_prepare(module, attempt, expected, approval):
    rec = ORIGINAL_PREPARE(module, attempt, expected, approval)
    server_start(module, attempt)        # a failure here leaves prepared=False in lab.run_all: sink_restore follows
    return rec


def sink_restore(module, attempt, expected, approval):
    error = None
    try:
        server_stop(module, attempt)
    except Exception as e:               # restore the sinkhole and DNS first; report the server after
        error = e
    rec = ORIGINAL_RESTORE(module, attempt, expected, approval)
    if error is not None:
        raise error
    return rec


lab.sink_prepare, lab.sink_restore = sink_prepare, sink_restore


# ------------------------------------------------------------------------------------------------- freeze

EXPECTATIONS = {
    "pools": {
        "paper_sb_nb": "the paper's Table V pool in the session lab (main + rest + floods, the dataset's 2 rejected "
                       "malware left out) + the silent-server benign batch + this batch",
        "base_nb": "every run of base/20261117b (main, tpilot, floods, triage, rest, silentbenign) + this batch",
        "rows_of_this_batch": "its 53 benign tasks; its 3 nulls; batch_control repeats left out of every pool"},
    "method": "build_base.py rows (relaxed rule, sessions view, program windows from the injection), grouped 5-fold CV "
              "over 10 fold assignments (malware family, attack instance, benign project held out; the lab tools by "
              "traffic shape, the first word of the task name, as in earlier runs), threshold 0.5, the paper's four "
              "detectors on the release's 90 host + 145 network columns; 20 s primary, 80 s secondary; Table V format "
              "(BA, recall, specificity, precision, F1, AUC; mean and sd); detector minus host per assignment",
    "references": "the same pools without this batch, base/20261117b (table45/table5_paper_sb.json, table5_base.json): "
                  "paper_sb 20 s BA host 0.828, network 0.645, concatenated 0.834, stacked 0.818; base 20 s host 0.842, "
                  "network 0.715, concatenated 0.866, stacked 0.852; network specificity on network-active benign "
                  "0.33 (paper_sb) and 0.34 (base)",
    "questions": {
        "Q1_network_false_alarms": "network specificity on the network-active benign rows of the earlier runs (not this "
                                   "batch's), with this batch in training: 'fewer false alarms' if it rises by >= 0.10 "
                                   "over the reference (base_nb and paper_sb_nb, 20 s)",
        "Q2_hybrid_over_host": "concatenated or stacked minus host >= +0.02 in >= 8 of 10 assignments on base_nb, 20 s: "
                               "'the hybrid adds over host'",
        "Q3_original_rows": "each detector's BA over the earlier runs' rows only (this batch in training) next to the "
                            "reference BA; reported, no threshold (fold assignments differ, so not paired)",
        "Q4_transfer": "detectors trained on all rows of base/20261117b, applied once to this batch's benign rows: flag "
                       "rate per detector, program and shape (never-seen benign); reported"},
    "also": ["per stratum and per group flags, new groups", "baselines (activity, lifetime, injection time, batch, mode) "
             "and the random-feature reference", "the silent-listener cue over all runs", "strict rule; unique view",
             "sensitivity: the lab tools grouped by program (webfetch, netpoll) instead of by shape",
             "batch check: the 3 batch_control repeats against their main/rest sessions of the same task "
             "(feature rank correlation, decisions)"],
    "prediction": "network specificity on network-active benign rises; the hybrids gain specificity with recall about "
                  "unchanged; overall BA rises a little, partly because the pool gains benign rows that are easy "
                  "(Q3 isolates the training effect)",
    "not_changed_after_results": "pools, groups, spans, detectors, thresholds, the questions' rules"}


def freeze(out_root=None):
    out_root = Path(out_root or HERE / "runs")
    plan = specs()
    tools = tool_set()
    for name, (path, want) in lab.TOOLS.items():
        require(Path(path).is_file() and sha256(path) == want, "tool %s missing or changed" % name)
    build_samples(lab.REV5)
    for s in plan:
        if s.get("source") == "archive":
            path = lab.REV5 / s["archive"]
            require(path.is_file(), "archive missing: " + s["archive"])
            s["sha256"] = M.member_sha256(path)
            s["archive_sha256"] = sha256(path)
            if s["archive"] == LT_ZIP:
                require(s["sha256"] == LABT_SHA, "Go client member hash")
            elif s["kind"] != "null":
                require(s["archive_sha256"] == sha256(REV5_SAMPLES / s["archive"]), "copy differs: " + s["archive"])
    run_id = lab.stamp()
    attempt = out_root / run_id
    (attempt / "plans").mkdir(parents=True)
    (attempt / "fixtures").mkdir()                   # none: inputs are guest system files (/etc, /usr/share)
    rng_t = random.Random(SEED + 1)
    sessions = []
    for i, spec in enumerate(plan, 1):
        s = dict(spec, sid="n%03d" % i, t_inject_s=round(rng_t.uniform(*lab.INJECT_RANGE), 3),
                 bg_seed=rng_t.randrange(1, 32768), marker="hz" + secrets.token_hex(6),
                 work="/tmp/" + secrets.token_hex(4))
        (attempt / "plans" / (s["sid"] + ".env")).write_text(M.plan_env(s))
        s["plan_sha256"] = sha256(attempt / "plans" / (s["sid"] + ".env"))
        sessions.append(s)
    counts = {}
    for s in sessions:
        k = s["kind"] + (":control" if s.get("batch_control") else "")
        counts[k] = counts.get(k, 0) + 1
    programs = {}
    for s in sessions:
        if s["kind"] == "benign" and not s.get("batch_control"):
            programs[s["program"]] = programs.get(s["program"], 0) + 1
    protocol = {
        "format": lab.FORMAT, "plan": "network-active-benign", "run_id": run_id, "frozen_utc": now_utc(),
        "duration_s": lab.DUR_S, "inject_range_s": list(lab.INJECT_RANGE), "window_s": 0.5, "sessions": sessions,
        "counts": counts, "programs": programs,
        "why": "the network view flags most network-active benign programs (base/20261117b: specificity 0.33-0.34); "
               "the benign side has few programs that use the network; these add the same traffic shapes from several "
               "independent programs, all against answered servers",
        "expectations": EXPECTATIONS,
        "test_server": {"binary": str(LABT), "sha256": LABT_SHA, "sink_folder": SINK_LAB,
                        "command": "labtransport server -addr 10.0.0.1",
                        "ports": {k: "%s/%d" % v for k, v in TEST_PORTS.items()},
                        "lifetime": "started after sink-prepare, stopped before sink-restore; its log fetched",
                        "used_by": "labtransport client, the Python client, curl/wget downloads, one openssl task"},
        "guest": {"vm": "Ubuntu-Clean-24.04", "baseline": lab.base.BASELINE, "baseline_uuid": lab.base.BASELINE_UUID,
                  "original": lab.base.ORIGINAL, "original_uuid": lab.base.ORIGINAL_UUID, "user": lab.GUEST_USER},
        "sink": {"vm": lab.SINK_VM, "capture": "tcpdump -i enp0s3 -n -U --immediate-mode -B 65536 -Z root (full frames)",
                 "capture_dir": lab.SINK_CAP, "sinkhole": "on during the sessions", "dns_answer": lab.DNS_REDIRECT,
                 "redirect_conf": lab.REDIRECT_DNSMASQ_CONF, "redirect_conf_sha256": lab.REDIRECT_CONF_SHA256,
                 "after": "sinkhole off, original dnsmasq, test server stopped"},
        "files": {name: sha256(lab.GUEST / name) for name in lab.GUEST_FILES},
        "tools": {name: {"source": str(path), "sha256": want} for name, (path, want) in tools.items()},
        "fixtures": {}, "fixture_guest_root": M.REV5_GUEST_ROOT,
        "samples_dir": str(SAMPLES), "background_scale_pm": M.BG_SCALE_PM,
        "driver_sha256": sha256(lab.__file__), "main_driver_sha256": sha256(M.__file__),
        "netbenign_driver_sha256": sha256(__file__), "approval": None, "retries": False,
        "replaces": {"attempt": "20261117T105520781257Z", "stopped_after": "n005 (5 sessions accepted, n006 interrupted)",
                     "why": "the musl builds' name-based tasks could not resolve names in the lab (dnsmasq refuses "
                            "AAAA; musl fails the lookup): the two name-based curl tasks now run on the glibc build "
                            "(curl-pop3 and curl-smtps moved to the i386 build, so the mode counts are unchanged), the "
                            "two wget tasks ask for IPv4 only", "used": False},
        "malware": "none in this batch",
        "keep_going": "a rejected/failed session is recorded; %d in a row stop the run" % M.MAX_IN_A_ROW,
        "merge_with_any_dataset": False, "model_fitting": False,
        "limitations": ["lab-written clients and the dataset's builds, not a user's real workload",
                        "servers are INetSim, dnsmasq and our test server, not real services",
                        "generated background", "one batch", "separate collection; never merged"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": sha256(attempt / "protocol.json"),
                      "counts": counts, "programs": programs}, indent=1))
    return attempt


# --------------------------------------------------------------------------------------------------- self-test

class FakeHelper(M.FakeHelper):
    """main's fake VirtualBox plus the Sink side of the test server."""
    def __init__(self, folder, fail=None, uuids=None):
        super().__init__(folder, fail, uuids)
        self.server = "stopped"
        self.server_events = []

    def vbox(self, *args, check=True):
        if args[:1] == ("guestcontrol",) and args[1] == lab.SINK_VM:
            verb = args[2]
            if verb == "run":
                rest = list(args[args.index("--") + 1:])
                exe = args[args.index("--exe") + 1]
                text = " ".join(rest)
                if "pkill -x labtransport; echo ok" in text:
                    self.calls.append(args)
                    return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")
                if exe == "/usr/bin/sha256sum" and rest[-1].endswith("/labtransport"):
                    self.calls.append(args)
                    return SimpleNamespace(returncode=0, stdout="%s  %s\n" % (LABT_SHA, rest[-1]), stderr="")
                if "labtransport server" in text:
                    self.calls.append(args)
                    self.server = "running"
                    self.server_events.append("start")
                    return SimpleNamespace(returncode=0, stdout="4321\n", stderr="")
                if "kill $(cat server.pid)" in text:
                    self.calls.append(args)
                    self.server = "stopped"
                    self.server_events.append("stop")
                    return SimpleNamespace(returncode=0, stdout="stopped\n", stderr="")
                if "ss -Hltnu" in text:
                    out = super().vbox(*args, check=check)
                    if self.server == "running":
                        out.stdout = (out.stdout or "") + "".join(
                            "%s LISTEN 0 5 10.0.0.1:%d 0.0.0.0:*\n" % (proto, port) for proto, port in TEST_PORTS.values())
                    return out
            elif verb == "copyfrom" and "/server-" in args[-2] and args[-2].endswith(".log"):
                self.calls.append(args)
                Path(args[-1]).write_text('{"event":"ready"}\n')
                return SimpleNamespace(returncode=0, stdout="", stderr="")
        return super().vbox(*args, check=check)


def self_test():
    plan = specs()
    benign = [s for s in plan if s["kind"] == "benign" and not s.get("batch_control")]
    controls = [s for s in plan if s.get("batch_control")]
    names = [s["name"] for s in plan if s["kind"] == "benign"]
    require(len(names) == len(set(names)), "duplicate benign session names")
    require(len(benign) == 53 and len(controls) == 3, "expected 53 benign tasks and 3 batch controls")
    kinds = {k: sum(1 for s in plan if s["kind"] == k) for k in ("benign", "null", "none", "malware")}
    require(kinds == {"benign": 56, "null": 3, "none": 3, "malware": 0}, "composition %s" % kinds)
    for s in benign:
        require(s.get("destinations") and destinations_ok(s["destinations"]), "destination not allowed: " + s["name"])
        for d in s["destinations"]:
            host, port = d.rsplit(":", 1)
            flat = " ".join(s["args"])
            stem = ".".join(host.split(".")[:3]) if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else host.split(".", 1)[-1]
            require(stem in flat, "destination not in the arguments: " + s["name"])
        require(not any("64999" in a for a in s["args"]), "task names the silent listener: " + s["name"])
    for s in benign:
        if s.get("source") == "tool" and s["tool"] == "webfetch" and s["args"][0] != "pyexec":
            require(s["args"][0] in ("beacon", "session", "bulk", "bulkup", "dns"), "webfetch attack mode: " + s["name"])
    groups = {}
    for s in benign:
        g = s.get("project") or s["name"].split("-")[0]
        groups[g] = groups.get(g, 0) + 1
    require(set(groups) >= {"curl", "wget", "openssl", "inetutils", "labtransport", "python-client", "checkin",
                            "browse", "download", "upload", "dns", "keepalive", "device"}, "groups %s" % groups)
    # the first 15 sessions cover every program
    first = {s.get("program") for s in plan[:15] if s["kind"] == "benign"}
    require({"curl", "wget", "openssl", "labtransport", "python-client", "webfetch", "netpoll"} <= first,
            "first 15 sessions miss a program: %s" % first)
    env = M.plan_env(dict(plan[0], sid="n001", t_inject_s=50.0, bg_seed=1, marker="hz000000000000", work="/tmp/x"))
    require("SCALE_PM=%d" % M.BG_SCALE_PM in env, "plan.env lacks the 4x background")
    py = next(s for s in benign if s["program"] == "python-client")
    env = M.plan_env(dict(py, sid="n002", t_inject_s=50.0, bg_seed=1, marker="hz000000000001", work="/tmp/y"))
    require("INJ_SOURCE=tool" in env and "INJ_TOOL=webfetch" in env and "transport_client.py" in env, "pyexec plan")
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        global SAMPLES
        keep_samples, keep_rev5 = SAMPLES, lab.REV5
        SAMPLES = folder / "samples"
        lab.REV5 = SAMPLES
        try:
            attempt = freeze(folder / "runs")
            expected = sha256(attempt / "protocol.json")
            protocol = load(attempt / "protocol.json")
            require("transport_client.py" in protocol["tools"], "Python client not staged")
            lt = [s for s in protocol["sessions"] if s.get("archive") == LT_ZIP]
            require(lt and all(s["sha256"] == LABT_SHA for s in lt), "Go client archive")
            helper = FakeHelper(folder, None)

            def wait_guest(h, auth, log):
                h.vbox("startvm", h.VM, "--type", "headless")
                Path(log).write_text("booted\n")
            fake = SimpleNamespace(helper=helper, wait_guest=wait_guest, check_competitors=lambda: None,
                                   sleep=lambda x: None)
            picked = [s["sid"] for s in protocol["sessions"][:4]]
            picked += [next(s["sid"] for s in protocol["sessions"] if s.get("archive") == LT_ZIP),
                       next(s["sid"] for s in protocol["sessions"] if s.get("program") == "python-client"),
                       next(s["sid"] for s in protocol["sessions"] if s.get("batch_control"))]
            only = set(picked)
            keep = lab.sessions_phase
            try:
                M.run_all(attempt, expected, "self-test approval", real=fake, only=only)
            finally:
                lab.sessions_phase = keep
            done = {q.parent.name: load(q)["status"] for q in (attempt / "sessions").glob("*/result.json")}
            require(set(done) == only and all(v == "accepted" for v in done.values()), "fake run: %s" % done)
            require(helper.state == "poweroff" and helper.current == lab.base.ORIGINAL and helper.sinkhole == "off",
                    "fake run: not restored")
            require(helper.server_events == ["start", "stop"] and helper.server == "stopped", "test server lifecycle")
            sd = attempt / "phases" / "test-server"
            require(len(list(sd.glob("start-*.json"))) == 1 and load(sorted(sd.glob("start-*.json"))[-1])["status"]
                    == "passed", "server start record")
            stop = load(sorted(sd.glob("stop-*.json"))[-1])
            require(stop["status"] == "passed" and stop.get("log_fetched"), "server stop record")
            staged = [v for k, v in helper.guest_files.items() if k.endswith("/transport_client.py")]
            require(staged and Path(staged[-1]) == PYCLIENT, "Python client not copied to the guest")
            samples = [v for k, v in helper.guest_files.items() if k.endswith("/sample.zip")]
            require(any(Path(v).name == LT_ZIP for v in samples), "Go client archive not copied to the guest")
            # a failed server start still restores the sinkhole and DNS
            helper2 = FakeHelper(folder, None)
            orig = server_listening

            def never(module):
                return {k: False for k in TEST_PORTS}
            globals()["server_listening"] = never
            fake2 = SimpleNamespace(helper=helper2, wait_guest=wait_guest, check_competitors=lambda: None,
                                    sleep=lambda x: None)
            attempt2 = freeze(folder / "runs2")
            expected2 = sha256(attempt2 / "protocol.json")
            try:
                M.run_all(attempt2, expected2, "self-test approval", real=fake2,
                          only={load(attempt2 / "protocol.json")["sessions"][0]["sid"]})
                raise AssertionError("server start failure not raised")
            except Exception as error:
                require("not listening" in str(error) or "still running" in str(error), "unexpected error %s" % error)
            finally:
                globals()["server_listening"] = orig
            require(helper2.sinkhole == "off" and helper2.dns == lab.DNS_ORIGINAL, "restore after a failed start")
            require(not (attempt2 / "sessions").exists() or not list((attempt2 / "sessions").glob("*/result.json")),
                    "sessions ran after a failed server start")
        finally:
            SAMPLES, lab.REV5 = keep_samples, keep_rev5
    print(json.dumps({"self_test": "ok", "fake_run_sessions": len(done), "sessions": len(plan), "kinds": kinds,
                      "groups": groups, "programs": sorted({s["program"] for s in benign}),
                      "modes": {m: sum(1 for s in benign if (s.get("mode") or "native_amd64_static") == m)
                                for m in ("native_amd64_dynamic", "native_amd64_static", "native_i386_static")}},
                     indent=1))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--run-all", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.run_all:
        M.run_all(Path(a.attempt).resolve(), a.protocol_sha256, a.approval)
    else:
        p.error("choose --self-test, --freeze-only or --run-all")


if __name__ == "__main__":
    main()
