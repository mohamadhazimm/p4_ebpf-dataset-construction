"""Benign-only payload: the 62 paper benign tasks that are NOT in the bursty run, + 3 nulls.

build_benign_bursty_payload.select_short() took 2 tasks per project (43). This builder takes the complement, so the
bursty run + this run = all 105 of the paper's benign tasks observed for 5 min. Same mechanics as the bursty builder
(transports, arguments and fixtures verbatim, only the guest root rewritten; nulls from revision5); no sparse jobs.
The selection is the whole remainder -- nothing is picked by outcome. No VM, no sample execution.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build_benign_bursty_payload as bbp  # noqa: E402

REV5_PAYLOAD = bbp.REV5_PAYLOAD
SELECT_SHORT = bbp.select_short          # the original, captured before build() substitutes select_rest for it


def select_rest():
    planned = {c["sample"] for c in SELECT_SHORT()}
    cases = json.load(open(REV5_PAYLOAD / "cases.json"))
    rest = [c for c in cases if c["label"] == "benign" and c["sample"] not in planned]
    return sorted(rest, key=lambda c: (c["project"], c["program"], c["sample"]))


def build(out_dir, guest_root):
    """bbp.build looks up select_short / SPARSE at call time, so the complement is substituted for the duration."""
    saved = (bbp.select_short, bbp.SPARSE)
    bbp.select_short, bbp.SPARSE = select_rest, []
    try:
        return bbp.build(out_dir, guest_root)
    finally:
        bbp.select_short, bbp.SPARSE = saved


def _self_test():
    import re
    import tempfile
    root = "/home/csci/Downloads/benrest-selftest"
    rest = select_rest()
    short = bbp.select_short()
    assert len(rest) == 62 and len(short) == 43, (len(rest), len(short))
    assert not ({c["sample"] for c in rest} & {c["sample"] for c in short}), "overlap with the bursty run"
    allb = {c["sample"] for c in json.load(open(REV5_PAYLOAD / "cases.json")) if c["label"] == "benign"}
    assert {c["sample"] for c in rest} | {c["sample"] for c in short} == allb, "together they must be all 105"
    with tempfile.TemporaryDirectory(prefix="hazim-benrest-") as d:
        manifest, order = build(Path(d) / "payload", root)
        print("counts:", manifest["counts"], "| by_kind:", manifest["by_kind"], "| by_project:", manifest["by_project"])
        assert manifest["counts"] == {"benign": 62, "null": 3} and manifest["by_kind"] == {"short": 62, "null": 3}
        assert len({c["sample"] for c in order}) == len(order)
        for c in order:
            args = json.load(open(Path(d) / "payload/arguments" / (c["sample"] + ".json")))
            assert bbp.REV5_ROOT not in json.dumps(args), "stale revision5 root in " + c["sample"]
            for a in args:
                for p in re.findall(re.escape(root) + r"/(fixtures/[^\s]+)", a):
                    assert (Path(d) / "payload" / p.rstrip("/")).exists(), "missing payload path " + p
        for s in manifest["short_tasks"]:
            assert (Path(d) / "payload/samples" / s).read_bytes() == (REV5_PAYLOAD / "samples" / s).read_bytes(), s
    print("PASS build_benign_rest_payload self-test: 62 short (complement of the bursty 43 = all 105) + 3 null, "
          "no stale root, fixture paths present, transports verified")


if __name__ == "__main__":
    _self_test()
