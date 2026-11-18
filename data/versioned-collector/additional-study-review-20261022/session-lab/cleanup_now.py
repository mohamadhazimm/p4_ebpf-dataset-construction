#!/usr/bin/env python3
"""Put both VMs back after an interrupted session-lab run: stop any Sink capture, original dnsmasq and sinkhole
off (checked), guest powered off and restored to the original clean snapshot (checked). Only for a run whose
driver was stopped; refuses while a session-lab driver is still running.

  /usr/bin/python3 cleanup_now.py --attempt DIR --approval "<user's words>"
"""
import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_session_lab as lab  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--attempt", required=True)
    p.add_argument("--approval", required=True)
    a = p.parse_args()
    lab.require(a.approval.strip(), "approval required")
    running = subprocess.run(["pgrep", "-f", "run_session_(lab|main).py --run-all"], capture_output=True, text=True)
    lab.require(not running.stdout.strip(), "a session-lab driver is still running: %s" % running.stdout.strip())
    deps = lab.base.real_deps()
    module = deps.helper
    attempt = Path(a.attempt).resolve()
    protocol = lab.load(attempt / "protocol.json")
    expected = lab.sha256(attempt / "protocol.json")
    try:
        lab.sink_restore(module, attempt, expected, a.approval)
    finally:
        lab.base.power_off(module, deps)
        module.vbox("snapshot", module.VM, "restore", lab.base.ORIGINAL)
        final = lab.base.vm_states(module)
        print(final["guest"]["VMState"], final["guest"]["CurrentSnapshotName"], final["sink"]["VMState"],
              protocol["run_id"])


if __name__ == "__main__":
    main()
