"""Targeted short VM re-check of ONLY the rebalance backfill benign cases (no malware, no full re-preflight).

After the 2026-10-25 rebalance restored amd64-static benign to 59 by adding 5 guest-safe compute cases
(od/wc/sort/sum/sha256sum, coreutils), this stages a fresh benign child from the quiet baseline, runs the production
batch on JUST those 5 new samples, audits them with collect_revision5/collect_v21's exact technical + traffic gates,
and restores the original TLS snapshot. The other 100 benign are byte-identical to the already-validated preflight
set. Reuses the audited driver machinery; takes the common readiness lock; restores on every exit. One attempt.
"""
import argparse
import collections
import fcntl
import json
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_revision5 as c5  # noqa: E402

frozen, v21 = c5.frozen, c5.v21
require, digest, save, load, stamp = frozen.require, frozen.digest, frozen.save, frozen.load, frozen.stamp
NEW_PROGRAMS = {"od", "wc", "sort", "sum", "sha256sum"}  # the rebalance backfill


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--attempt", type=Path, required=True)
    parser.add_argument("--protocol-sha256", required=True)
    parser.add_argument("--approval", required=True)
    options = parser.parse_args()
    attempt, expected_hash, approval = options.attempt.resolve(), options.protocol_sha256, options.approval
    require(approval and approval.strip(), "A verbatim user approval is required for this VM re-check")
    protocol = c5.verify_plan(attempt, expected_hash)
    new = [c for c in protocol["cases"] if c.get("program") in NEW_PROGRAMS and c["mode"] == "native_amd64_static"]
    require(len(new) == 5, "expected exactly 5 backfill cases, found %d" % len(new))
    module = frozen.helper()
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        destination = attempt / "recheck" / stamp()
        destination.mkdir(parents=True, exist_ok=False)
        snapshot = "clean-rev5-recheck-" + destination.name
        sample_list = destination / "samples.txt"
        sample_list.write_text("".join(c["sample"] + "\n" for c in new))
        save(destination / "authorization.json", {"approval": approval, "protocol_sha256": expected_hash,
             "samples": [c["sample"] for c in new], "authorized_utc": datetime.now(timezone.utc).isoformat()})
        result = {"protocol_sha256": expected_hash, "status": "failed_preserved", "samples": [c["sample"] for c in new]}

        def interrupted(_s, _f):
            raise KeyboardInterrupt("Stop owned process group, restore original snapshot, preserve failure")
        previous = signal.signal(signal.SIGTERM, interrupted)
        touched = False
        try:
            save(destination / "initial_vm_state.json", v21.preflight(module, protocol))
            require(not v21.snapshot_present(module, snapshot), "Recheck child already exists")
            touched = True
            save(destination / "command.json", v21.stage_command(attempt, module, snapshot))
            frozen.run_logged(v21.stage_command(attempt, module, snapshot), destination / "stage.log", 1800)
            out = destination / "runs"
            frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, out, sample_list),
                              destination / "collection.log", 3600)
            tools = frozen.validation_tools()
            by = {c["sample"]: c for c in new}
            rows = []
            for c in new:
                row = {k: c.get(k) for k in ("sample", "mode", "program", "activity_bin", "network", "split")}
                try:
                    row.update(v21.audit_case_v21(out / c["sample"], c, protocol["settings_required"], tools),
                               status="accepted")
                except Exception as error:
                    row.update(status="excluded", reason=type(error).__name__ + ": " + str(error))
                rows.append(row)
            accepted = sum(1 for r in rows if r["status"] == "accepted")
            save(destination / "recheck.json", {"results": rows, "accepted": accepted, "total": len(rows),
                 "counts": dict(collections.Counter(r["status"] for r in rows))})
            result.update(accepted=accepted, total=len(rows), all_accepted=(accepted == len(rows)))
            require(accepted == len(rows), "Not all backfill cases accepted: %d/%d" % (accepted, len(rows)))
            result["status"] = "passed"
        except BaseException as error:
            result["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            try:
                if touched:
                    frozen.restore(module, destination)
            except BaseException as error:
                result.update(status="cleanup_failed_requires_user", cleanup_error=type(error).__name__ + ": " + str(error))
                raise
            finally:
                save(destination / "result.json", result)
                signal.signal(signal.SIGTERM, previous)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
