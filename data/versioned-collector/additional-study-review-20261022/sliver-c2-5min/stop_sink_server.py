"""Stop our Sliver server on the Sink after the testbed collection (offline-safe housekeeping on our own
lab process). Its WireGuard listener kept sending a packet every ~5 s to the last WireGuard implant's
guest port, which would appear in every later capture. Records the state before and after.

    /usr/bin/python3 stop_sink_server.py
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import collect_sinkhole_c2 as c2  # noqa: E402  credential-safe sink_run

LAB = "/home/remnux/hazim-sliver"
STATUS = ("pgrep -af sliver-server || echo 'no sliver-server process'; "
          "ss -lunp 2>/dev/null | grep -E ':51820|:53 ' || true; ss -ltn 2>/dev/null | grep -E ':(8443|8080|8444|31337) ' || echo 'no sliver TCP listeners'")


def run(module, script, sudo=False):
    r = c2.sink_run(module, ["/bin/bash", "-lc", script], sudo=sudo)
    return (r.stdout or "") + (r.stderr or "")


def main():
    module = c2.cp.frozen.helper()
    info = module.isolated(c2.SINK_VM)
    assert info["VMState"] == '"running"' and info.get("nic1") in ('"intnet"', "intnet"), "Sink not running/isolated"
    out = {"utc": datetime.now(timezone.utc).isoformat()}
    out["before"] = run(module, STATUS)
    out["kill"] = run(module, "cd %s && if [ -s daemon.pid ]; then kill -TERM $(cat daemon.pid) && echo sent; fi; "
                              "sleep 3; pkill -TERM -u remnux -f 'sliver-server_linux-amd64 daemon' && echo pkill || true"
                      % LAB)
    out["after"] = run(module, "sleep 2; " + STATUS)
    path = HERE / ("sink-server-stop-%s.json" % datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    path.write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
