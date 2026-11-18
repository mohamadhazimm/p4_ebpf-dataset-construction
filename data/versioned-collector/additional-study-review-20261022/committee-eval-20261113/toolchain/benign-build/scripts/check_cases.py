"""Host-run every proposed case's own task at its activity bin (benign programs only, unprivileged, stdin=/dev/null,
20-s timeout, private directory) with the same output verification as host_check.py. Network cases (Sink tasks)
and unchanged dataset cases are listed as not host-runnable / already guest-validated.

    /usr/bin/python3 -I scripts/check_cases.py <benign-build dir>
"""
import json
import shutil
import sys
from pathlib import Path

BB = Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], str(BB)]
sys.path.insert(0, str(BB / "scripts"))
import host_check as hc  # noqa: E402


def main():
    cases = json.loads((BB / "proposed_cases.json").read_text())
    tg = {(t["toolchain"], t["program"]): t for t in hc.targets()}
    for c in cases:
        if c["kind"] == "existing dataset case":
            c["host_check"] = {"status": "not rerun (existing dataset case, guest-validated in revision5)"}
            continue
        t = tg[(c["toolchain"], c["program"])]
        if c["network_task"]:
            spec = hc.spec_for(t, "light")
        else:
            spec = hc.spec_for(t, c["activity_bin"])
        cwd = BB / "checks/cases" / c["case_id"]
        shutil.rmtree(cwd, ignore_errors=True)
        paths, argv = hc.resolve(spec, cwd)
        res = hc.run(BB / t["bin"], argv, cwd)
        ok, how = hc.verify(t, spec, paths, res, cwd, argv, c["activity_bin"] or "light")
        c["host_check"] = {"status": "pass" if ok else "fail", "argv": argv, "rc": res["rc"],
                           "timeout": res["timeout"], "seconds": res["seconds"], "check": how,
                           "note": "network task needs the Sink; host run is a --version smoke test"
                           if c["network_task"] else ""}
        shutil.rmtree(cwd, ignore_errors=True)
        print("%-14s %-42s %-10s %-6s %s %ss %s" % (c["case_id"], c["toolchain"], c["program"], c["activity_bin"],
                                                   c["host_check"]["status"], res["seconds"], how), flush=True)
    (BB / "proposed_cases.json").write_text(json.dumps(cases, indent=1))


if __name__ == "__main__":
    main()
