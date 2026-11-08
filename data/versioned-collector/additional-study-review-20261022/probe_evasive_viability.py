"""Host-evasive reverse-shell/backdoor VIABILITY PROBE (Rekoobe + BPFDoor).

Second viability probe (after probe_c2_viability), on the newly-sourced host-quiet class: 16 Rekoobe (active
TinyShell-derived reverse-shell backdoor) + 4 BPFDoor (passive magic-packet backdoor), all native amd64. Same
measurement as the C2 probe: per sample host activity vs in-window network flow vs exec status, run through the
installed `.21` collector in the isolated quiet guest against the Sink. Expected: Rekoobe replicates the host-evasive
signature (host-quiet + a real flow, like the 4 Meterpreter that worked); BPFDoor is passive and should sit SILENT on
both channels against a Sink that never sends its trigger magic packet -- a prediction this probe tests.

Reuses probe_c2_viability's tested helpers (inspect_elf/extract_member/sum_inwindow_net_packets/perform_phase/
verify_plan/measure) and the collect_v21/build_v21_payload VM-safety + payload machinery; only the sample set and a
skip-unsupported selection (4 Rekoobe are static-PIE -> dropped) differ. NO acceptance gate, NO model, NO merge;
per-phase VM approval required, same gates. Viability only, not a classifier cohort.
"""

import argparse
import collections
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import probe_c2_viability as base   # noqa: E402  reuse ELF/measure/phase helpers + VM machinery
import collect_v21 as v21          # noqa: E402
import build_v21_payload as builder  # noqa: E402
import collect_v19 as frozen       # noqa: E402

STUDY = frozen.STUDY
require, digest, save, load, stamp = frozen.require, frozen.digest, frozen.save, frozen.load, frozen.stamp
EVASIVE_MB = STUDY / "data/malware/revision5-diverse/evasive-incoming"
EVASIVE_TRIAGE = STUDY / "data/malware/revision5-diverse/triage-evasive"
NULL_MODES = ["native_amd64_dynamic", "native_amd64_static"]   # all evasive malware is amd64

MBFAM = {  # evasive-incoming (MB) member hashes -> family (from get_siginfo census)
    "4435fcd6862921092614dbeaa880e4192352984686ebcd98f0ba13ee8e226ef9": "Rekoobe",
    "1adee8d0140c7578c39122fe9fff10a3c4da3f069a1c73aeedeb9c16b2867212": "Rekoobe",
    "46ce4b0fbe106258d9acd3af171106d85c0332079d489b391c35d592cefa030f": "Rekoobe",
    "672fef6902b0e20024f0af11f62f7a13c14db045ac418e5fab6f7c9beaa44977": "Rekoobe",
    "2cc90edd9bc085f54851bed101f95ce2bace7c9a963380cfd11ea0bc60e71e0c": "BPFDoor",
    "de472ed37e33b79e1aa37e67a680ee3a9d74628438c209543a06e916a0a86fba": "BPFDoor",
    "3b071d36ffa393a8891832590304b21ee9017b4977a747917e6c6116596851da": "BPFDoor",
    "3e01a4bd73b3567f59bd80c7349e3b7ce85c15a6d94016ddfcd0bf3f239684dc": "BPFDoor",
}


def generate_selection():
    """Scan the evasive quarantine; keep supported native modes (skip static-PIE), map family."""
    cases = []
    for z in sorted(EVASIVE_MB.glob("*.zip")):
        member = base.extract_member(z)
        sha = hashlib.sha256(member).hexdigest()
        require(sha == z.stem, "MB member hash != archive name: " + z.name)
        mode = base.inspect_elf(member)
        if not mode.startswith("native"):
            continue
        require(sha in MBFAM, "unmapped MB family: " + sha)
        cases.append({"member_sha256": sha, "source_path": str(z.relative_to(STUDY)), "transport_ready": True,
                      "mode": mode, "family": MBFAM[sha], "split": "probe"})
    for f in sorted(EVASIVE_TRIAGE.iterdir()):
        if not f.is_file() or f.suffix == ".jsonl":
            continue
        data = f.read_bytes()
        if data[:4] != b"\x7fELF":
            continue
        sha = hashlib.sha256(data).hexdigest()
        mode = base.inspect_elf(data)
        if not mode.startswith("native"):   # the 4 static-PIE Rekoobe are dropped here
            continue
        cases.append({"member_sha256": sha, "source_path": str(f.relative_to(STUDY)), "transport_ready": False,
                      "mode": mode, "family": "Rekoobe", "split": "probe"})  # triage-evasive pull = Rekoobe only
    require(len(cases) >= 18, "too few evasive cases: %d" % len(cases))
    require(len({c["member_sha256"] for c in cases}) == len(cases), "duplicate member hash")
    nulls = [{"mode": m, "spot": s} for m in NULL_MODES for s in ("start", "middle", "end")]
    return {"cases": cases}, {"cases": [], "nulls": nulls}


def freeze():
    v21.verify_production()
    run_id = stamp()
    attempt = ROOT / "evasive-viability" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/evasive-probe-" + run_id
    sel, null_bind = generate_selection()
    save(attempt / "evasive_selection.json", sel)
    save(attempt / "null_binding.json", null_bind)
    workdir = attempt / "_wrap"
    workdir.mkdir()
    manifest, order = builder.build(attempt / "payload", sel, null_bind, guest_root, workdir)
    subprocess.run(["rm", "-rf", str(workdir)], check=False)
    payload_bytes = v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = v21.build_setup(guest_root, payload_bytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    by_family = dict(collections.Counter((c["family"], c["mode"]) for c in order if c["label"] == "malware"))
    protocol = {
        # same format string as the C2 probe so base.verify_plan/perform_phase accept it unchanged; the attempt dir
        # + selection distinguish the two probes.
        "format": "c2-viability-probe-v1", "sample_set": "evasive-rekoobe-bpfdoor", "schema": v21.SCHEMA,
        "production_hashes": v21.PINNED,
        "purpose": "host-evasive viability probe on Rekoobe + BPFDoor; measure host-activity vs network-flow against "
                   "the isolated Sink; NOT a cohort, NO gate, NO model, NO merge",
        "baseline_snapshot": v21.BASELINE, "baseline_uuid": v21.BASELINE_UUID, "original_uuid": v21.ORIGINAL_UUID,
        "new_snapshot": "clean-evasiveprobe-" + run_id, "guest_root": guest_root, "settings": v21.SETTINGS,
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "malware_by_family_mode": {f"{k}": n for k, n in sorted(by_family.items())},
        "evasive_selection_sha256": digest(attempt / "evasive_selection.json"),
        "null_binding_sha256": digest(attempt / "null_binding.json"),
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(builder.__file__)), "driver_sha256": digest(__file__),
        "approval": None, "vm_steps_authorized": [], "retries": False, "resume": False, "replacement": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt")},
        "limitations": [
            "Rekoobe is a tiny TinyShell-derived backdoor; the 16 are near-duplicate (~3-4 distinct builds).",
            "BPFDoor is passive (waits for an inbound magic packet); against a Sink that never sends it, expect "
            "silent-both. This probe TESTS that prediction; it is not padding the active class.",
            "All amd64; the confirmed i386 Meterpreter win is not represented here.",
            "Viability only; not a classifier cohort, not an evaluation, merges no dataset."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "malware_by_family_mode": protocol["malware_by_family_mode"],
                      "payload_mb": round((attempt / "payload.tgz").stat().st_size / 1048576),
                      "new_snapshot": protocol["new_snapshot"]}, indent=2))
    return attempt


def self_test():
    sel, null_bind = generate_selection()
    bymode = collections.Counter(c["mode"] for c in sel["cases"])
    byfam = collections.Counter(c["family"] for c in sel["cases"])
    assert len(sel["cases"]) == 20, len(sel["cases"])
    assert byfam["Rekoobe"] == 16 and byfam["BPFDoor"] == 4, byfam
    assert bymode["native_amd64_dynamic"] == 18 and bymode["native_amd64_static"] == 2, bymode
    assert all(c["mode"].startswith("native") for c in sel["cases"])
    assert len(null_bind["nulls"]) == 6 and null_bind["cases"] == []
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        manifest, order = builder.build(td / "payload", sel, null_bind, "/home/csci/Downloads/evasive-test", td / "_w")
        assert manifest["counts"].get("malware") == 20 and manifest["counts"].get("null") == 6, manifest["counts"]
        assert manifest["counts"].get("benign", 0) == 0 and len(order) == 26
        for c in order:
            assert (td / "payload/samples" / c["sample"]).is_file()
    print("self-test OK: evasive selection 16 Rekoobe + 4 BPFDoor (amd64-dyn 18 / amd64-static 2), payload 20+6")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--phase", choices=["preflight", "stage", "dry-run", "collect"])
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    p.add_argument("--measure", action="store_true")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.measure:
        base.measure(Path(a.attempt))          # generic: reads protocol.json + runs/
    elif a.phase:
        base.perform_phase(Path(a.attempt), a.phase, a.protocol_sha256, a.approval)  # generic (format matches)
    else:
        p.error("one of --self-test / --freeze-only / --phase / --measure required")


if __name__ == "__main__":
    main()
