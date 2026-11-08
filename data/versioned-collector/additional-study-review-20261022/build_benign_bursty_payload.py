"""Benign-only payload for the 5-min follow-up that adds the two benign SHAPES the 5-min cohort lacked.

WHY (host-gap check 2026-11-07, host-gap-check-20261107/): in the 5-min cohort the single feature "number of windows
with any system calls" scores BA 0.81-0.84 on its own, because every working benign program is busy for the whole
5 min, while 48 of 102 malware are active only in their first second and ~19 more wake only every ~10-25 s late in the
run. The detectors can lean on that instead of on behaviour. This run adds the missing shapes:

  SHORT  -- 43 of the paper's own guest-validated benign tasks (revision5 payload, all 24 projects, 2 per project where
            available; deterministic pick: the first case by (program, sample), then the first case of a DIFFERENT
            program, else the next case). Transport, arguments and fixtures reused verbatim; only the guest root is
            rewritten. They run for about a second and exit, so the rest of the 5 min is quiet -- the shape of most
            of the malware.
  SPARSE -- 15 periodic jobs that wake every 5-30 s: vmstat and free (procps) every 10/20/30 s; ping (inetutils i386
            musl, ICMP) every 10/20/30 s; wget --wait 10/20/30 s (i386); lowrate_gen poll/dns/tlspoll every 5/10/20 s
            for 60 s (its maximum duration), then exit.
NOT used: top (its static build segfaults in this guest, rc -11) and lowrate beyond 60 s (rejected with rc 2) -- both
found 2026-11-07 in the benign-expanded runs. Nulls reused verbatim from the revision5 payload.
Reuses build_v21_payload.plain_zip/sha256_bytes, benign_workloads_expanded.workload/BIN/materialize and
benign_workloads_long.resolve_argv unchanged. No VM, no sample execution. Run the self-test with /usr/bin/python3.
"""
import json
import math
import random
import re
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build_v21_payload as v21b                 # noqa: E402  sha256_bytes / plain_zip
import benign_workloads_expanded as be           # noqa: E402  workload / BIN / materialize / SINK
import benign_workloads_long as bl               # noqa: E402  resolve_argv

STUDY = ROOT.parents[2]
REV5 = ROOT / "revision5-collection/20261025T100025568989Z"
REV5_PAYLOAD = REV5 / "payload"
REV5_ROOT = json.load(open(REV5 / "protocol.json"))["guest_root"]
FIX_RE = re.compile(re.escape(REV5_ROOT) + r"/fixtures/rev5/([^/\s]+)")
PING_BIN = ("native_i386_static",
            "data/versioned-collector/additional-study-review-20261022/i386-network-builds/20261024T163419Z/bin/ping")
NULL_SAMPLES = {
    "native_amd64_static": "null-native_amd64_static-start.zip",
    "native_i386_static": "null-native_i386_static-start.zip",
    "native_amd64_dynamic": "null-native_amd64_dynamic-start.zip",
}
EXEC_NAME = {"lowrate": "lowrate_gen"}            # member basename inside the transport (as in benign-expanded)
PROJECT = {"vmstat": "procps", "free": "procps", "ping": "inetutils", "wget": "wget", "lowrate": "lowrate"}
SPARSE = ([("vmstat-d%d" % d, "vmstat", {"d": d}) for d in (10, 20, 30)]
          + [("free-s%d" % d, "free", {"d": d}) for d in (10, 20, 30)]
          + [("ping-i%d" % i, "ping", {"i": i}) for i in (10, 20, 30)]
          + [("wget-wait%d" % w, "wget", {"wait": w}) for w in (10, 20, 30)]
          + [("lowrate-%s-p%d" % (m, p // 1000), "lowrate", {"mode": m, "period_ms": p})
             for m, p in (("poll", 5000), ("dns", 10000), ("tlspoll", 20000))])


def require(ok, msg):
    if not ok:
        raise ValueError(msg)


def select_short():
    """2 per project (where available), deterministic and outcome-independent."""
    cases = json.load(open(REV5_PAYLOAD / "cases.json"))
    by = defaultdict(list)
    for c in cases:
        if c["label"] == "benign":
            by[c["project"]].append(c)
    out = []
    for project in sorted(by):
        cs = sorted(by[project], key=lambda c: (c["program"], c["sample"]))
        pick = [cs[0]]
        other = [c for c in cs[1:] if c["program"] != cs[0]["program"]] or cs[1:]
        if other:
            pick.append(other[0])
        out += pick
    return out


def sparse_spec(program, params):
    """(binary_key, mode, binary_path, argv-spec, fixtures, network)."""
    sink = be.SINK
    if program in ("vmstat", "free"):
        s = be.workload(program, {"d": params["d"]})               # count = round(320/d)+2 -> runs > 300 s
        return program, s["mode"], be.BIN[program][1], s["argv"], s["fixtures"], False
    if program == "ping":
        i = params["i"]
        argv = ["-n", "-i", str(i), "-c", str(330 // i + 2), "-w", "330", sink]
        return "ping", PING_BIN[0], PING_BIN[1], argv, [], True
    if program == "wget":
        w = params["wait"]
        s = be.workload("wget", {"urls": int(math.ceil(320 / w)) + 1})   # ~(urls-1)*w >= 320 s of paced GETs
        argv = ["-q", "--wait=%g" % w] + list(s["argv"][1:])
        return "wget", s["mode"], be.BIN["wget"][1], argv, s["fixtures"], True
    if program == "lowrate":
        argv = [params["mode"], str(params["period_ms"]), "60000", sink]    # 60 s = lowrate_gen's maximum
        return "lowrate", be.BIN["lowrate"][0], be.BIN["lowrate"][1], argv, [], True
    raise KeyError(program)


def _interleave(cases):
    nulls = sorted((c for c in cases if c["label"] == "null"), key=lambda c: c["mode"])
    ben = [c for c in cases if c["label"] == "benign"]
    random.Random(42).shuffle(ben)
    return nulls + ben


def build(out_dir, guest_root):
    out = Path(out_dir)
    for sub in ("samples", "arguments", "fixtures/rev5", "fixtures/sparse"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    rev5_manifest = json.load(open(REV5_PAYLOAD / "payload_manifest.json"))
    manifest = {"samples": {}, "arguments": {}, "short_tasks": {}, "sparse_jobs": {}}
    cases = []

    # SHORT: the paper's own validated benign tasks, verbatim except the guest root
    copied = set()
    for c in select_short():
        blob = (REV5_PAYLOAD / "samples" / c["sample"]).read_bytes()
        expected = rev5_manifest.get("samples", {}).get(c["sample"])
        require(expected is None or expected == v21b.sha256_bytes(blob), "revision5 transport changed: " + c["sample"])
        args = json.load(open(REV5_PAYLOAD / "arguments" / (c["sample"] + ".json")))
        new_args = []
        for a in args:
            if REV5_ROOT in a:
                names = FIX_RE.findall(a)
                require(names and a.count(REV5_ROOT) == len(names), "non-fixture guest path in " + c["sample"])
                for name in names:
                    src, dst = REV5_PAYLOAD / "fixtures/rev5" / name, out / "fixtures/rev5" / name
                    require(src.exists(), "missing fixture " + name)
                    if name not in copied:
                        (shutil.copytree if src.is_dir() else shutil.copy2)(src, dst)
                        copied.add(name)
                a = a.replace(REV5_ROOT, guest_root.rstrip("/"))
            new_args.append(a)
        (out / "samples" / c["sample"]).write_bytes(blob)
        (out / "arguments" / (c["sample"] + ".json")).write_text(json.dumps(new_args))
        manifest["samples"][c["sample"]] = v21b.sha256_bytes(blob)
        manifest["short_tasks"][c["sample"]] = {"project": c["project"], "program": c["program"], "mode": c["mode"],
                                                "network": c["network"], "revision5_args": args}
        cases.append({"sample": c["sample"], "label": "benign", "mode": c["mode"], "network": bool(c["network"]),
                      "program": c["program"], "project": c["project"], "variant": "short-" + c["program"],
                      "kind": "short", "expected_returncodes": c.get("expected_returncodes")})

    # SPARSE: periodic jobs with long intervals
    fixdir, cache = out / "fixtures/sparse", {}
    for name, program, params in SPARSE:
        key, mode, binpath, argv, fixtures, network = sparse_spec(program, params)
        binary = (STUDY / binpath).read_bytes()
        exec_name = EXEC_NAME.get(key, key)
        paths = {role: be.materialize(kind, size, fixdir, cache) for role, kind, size in fixtures}
        guest_paths = {role: guest_root.rstrip("/") + "/fixtures/sparse/" + p.name for role, p in paths.items()}
        args = bl.resolve_argv({"argv": argv}, guest_paths, ".")
        sample = "%s-%s.zip" % (mode, name)
        blob = v21b.plain_zip(exec_name, binary)
        (out / "samples" / sample).write_bytes(blob)
        (out / "arguments" / (sample + ".json")).write_text(json.dumps(args))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        manifest["sparse_jobs"][name] = {"program": program, "project": PROJECT[program], "mode": mode,
                                         "binary": exec_name, "binary_sha256": v21b.sha256_bytes(binary),
                                         "params": params, "args": args}
        cases.append({"sample": sample, "label": "benign", "mode": mode, "network": network, "program": program,
                      "project": PROJECT[program], "variant": name, "kind": "sparse"})

    for mode, sample in NULL_SAMPLES.items():
        blob = (REV5_PAYLOAD / "samples" / sample).read_bytes()
        (out / "samples" / sample).write_bytes(blob)
        shutil.copyfile(REV5_PAYLOAD / "arguments" / (sample + ".json"), out / "arguments" / (sample + ".json"))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        cases.append({"sample": sample, "label": "null", "mode": mode, "network": False, "spot": "start"})

    for a in (out / "arguments").iterdir():
        manifest["arguments"][a.name] = v21b.sha256_bytes(a.read_bytes())
    order = _interleave(cases)
    for i, c in enumerate(order, 1):
        c["position"] = i
    (out / "cases.json").write_text(json.dumps(order, indent=2))
    (out / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    manifest["counts"] = dict(Counter(c["label"] for c in order))
    manifest["by_kind"] = dict(Counter(c.get("kind", "null") for c in order))
    manifest["by_mode_label"] = {str(k): v for k, v in sorted(Counter((c["mode"], c["label"]) for c in order).items())}
    manifest["by_project"] = dict(sorted(Counter(c["project"] for c in order if c["label"] == "benign").items()))
    manifest["fixtures_copied"] = sorted(copied)
    (out / "payload_manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest, order


def _self_test():
    import hashlib
    import io
    import tempfile
    import zipfile
    root = "/home/csci/Downloads/benburst-selftest"
    with tempfile.TemporaryDirectory(prefix="hazim-benburst-") as d:
        manifest, order = build(Path(d) / "payload", root)
        print("counts:", manifest["counts"], "| by_kind:", manifest["by_kind"])
        print("by_project:", manifest["by_project"])
        print("by_mode_label:", manifest["by_mode_label"])
        print("fixtures copied:", manifest["fixtures_copied"])
        require(manifest["counts"] == {"benign": 58, "null": 3}, "counts")
        require(manifest["by_kind"] == {"short": 43, "sparse": 15, "null": 3}, "kinds")
        require(len({c["sample"] for c in order}) == len(order), "duplicate samples")
        require(len({c["project"] for c in order if c.get("kind") == "short"}) == 24, "not all 24 projects")
        require("top" not in {c.get("program") for c in order}, "top must not be used")
        for c in order:
            args = json.load(open(Path(d) / "payload/arguments" / (c["sample"] + ".json")))
            text = json.dumps(args)
            require(REV5_ROOT not in text, "stale revision5 root in " + c["sample"])
            for a in args:                                    # every guest path must exist inside the payload
                for p in re.findall(re.escape(root) + r"/(fixtures/[^\s]+)", a):
                    require((Path(d) / "payload" / p.rstrip("/")).exists(), "missing payload path " + p)
            if c.get("program") == "lowrate":
                require(args[2] == "60000" and int(args[1]) >= 100, "lowrate args out of range")
            if c.get("program") == "wget" and c.get("kind") == "sparse":
                require(any(a.startswith("--wait=") for a in args), "wget not paced")
        # sparse members are the on-disk binaries
        for name, job in manifest["sparse_jobs"].items():
            sample = "%s-%s.zip" % (job["mode"], name)
            z = zipfile.ZipFile(io.BytesIO((Path(d) / "payload/samples" / sample).read_bytes()))
            require(z.namelist() == [job["binary"]], "member name " + sample)
            require(hashlib.sha256(z.read(job["binary"])).hexdigest() == job["binary_sha256"], "member hash " + sample)
        # short transports are byte-identical to revision5
        for s in manifest["short_tasks"]:
            require((Path(d) / "payload/samples" / s).read_bytes() == (REV5_PAYLOAD / "samples" / s).read_bytes(), s)
        for name, job in manifest["sparse_jobs"].items():
            print("  %-18s %s" % (name, " ".join(job["args"])))
    print("PASS build_benign_bursty_payload self-test: 43 short (24 projects) + 15 sparse + 3 null, no top, "
          "lowrate <= 60 s, wget paced, no stale root, all fixture paths present, transports verified")


if __name__ == "__main__":
    _self_test()
