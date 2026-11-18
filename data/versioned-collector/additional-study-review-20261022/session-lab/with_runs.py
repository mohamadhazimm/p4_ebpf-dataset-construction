#!/usr/bin/env python3
"""Run a session-lab analysis script with extra runs known to build_base.py, without editing build_base.py (the
frozen silent-server benign batch's pre-registered scorer imports it unchanged).

  /usr/bin/python3 with_runs.py NAME=ATTEMPT [NAME=ATTEMPT ...] -- SCRIPT [ARGS ...]

Each NAME=ATTEMPT adds runs/ATTEMPT to build_base.RUNS and to the end of build_base.ORDER (collection order). The
target script is run as __main__ in this process, so its `import build_base` gets the patched module. Other scripts
can import this file and call register() / patch() themselves.

Two changes, both inert for runs without the flags:
  identity     used only by build_base.py's "unique" view (first session per program): a session marked
               `silent_server_task` or `new_task_args` reuses a dataset benign archive with new arguments, so its
               identity includes the arguments
  controls     a session marked `batch_control` (a repeat of a dataset task with its dataset arguments, run to check a
               batch's conditions) is left out of build_base.load_runs's rows; the left-out rows are kept in
               build_base.BATCH_CONTROL_ROWS
"""
import json
import runpy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_base as BB   # noqa: E402

_PATCHED = False


def register(name, att):
    assert (HERE / "runs" / att / "protocol.json").is_file(), att
    BB.RUNS[name] = att
    if name not in BB.ORDER:
        BB.ORDER.append(name)


def patch():
    global _PATCHED
    if _PATCHED:
        return
    _PATCHED = True
    original_identity, original_load = BB.identity, BB.load_runs

    def identity(s):
        if s.get("silent_server_task") or s.get("new_task_args"):
            return "%s:%s:%s" % (s["kind"], s.get("archive", ""), json.dumps(s.get("args", [])))
        return original_identity(s)

    def load_runs(names):
        out, skipped = original_load(names)
        keep = [s for s in out if not s.get("batch_control")]
        BB.BATCH_CONTROL_ROWS = [s for s in out if s.get("batch_control")]
        if len(keep) != len(out):
            skipped = dict(skipped, batch_control_left_out=len(out) - len(keep))
        return keep, skipped
    BB.identity, BB.load_runs = identity, load_runs
    BB.BATCH_CONTROL_ROWS = []


def main():
    argv = sys.argv[1:]
    if "--" not in argv:
        sys.exit(__doc__)
    cut = argv.index("--")
    for spec in argv[:cut]:
        name, att = spec.split("=", 1)
        register(name, att)
    patch()
    script = argv[cut + 1]
    sys.argv = [script] + argv[cut + 2:]
    if Path(script).name == "build_base.py":
        # run_path would give build_base.py a fresh namespace without the patch: call the patched module instead
        sys.exit(BB.main())
    runpy.run_path(str(HERE / script), run_name="__main__")


if __name__ == "__main__":
    main()
