"""Phase 1 of the bot-flooding experiment: PASSIVELY OBSERVE Gafgyt C2 handshakes (no flood commanded).

Runs two x86 Gafgyt samples once in the sealed quiet guest and reads each guest PCAP to learn how the bot dials its
hardcoded C2: destination IP:port, whether anything answered (SYN-ACK), and the first application payload it sends
(the IRC NICK/USER/JOIN or plaintext handshake). No controller is present, so the bot just attempts contact and
idles -- NOTHING is commanded, NO flood. Output drives the design of the contained lab controller (Phase 2).

Reuses probe_c2_viability's tested VM-safety machinery + build_v21_payload assembly (format string kept
"c2-viability-probe-v1" so base.perform_phase/verify_plan are reused unchanged). Guest is intnet-only (no route out).
Targets:
  478053ea9305... amd64-static  "Kaiten Ziggy Qbot Redo" IRC variant (documented UDP/TCP/HTTP/HOLD/JUNK, ENABLE gate)
  0004b57f7671... i386-static   plaintext variant (TCP/UDP/STOP), C2 158.255.7.44:6668
"""
import argparse, collections, json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import probe_c2_viability as base   # noqa: E402
import collect_v21 as v21           # noqa: E402
import build_v21_payload as builder  # noqa: E402
import collect_v19 as frozen        # noqa: E402

STUDY = frozen.STUDY
require, digest, save, load, stamp = frozen.require, frozen.digest, frozen.save, frozen.load, frozen.stamp
COHORT = "data/malware/full-cohort-323/samples"
TARGETS = [
    ("478053ea93052dd3f1477cf497443c0cb1b0e75361ba3927b929b707c18f35e2", "native_amd64_static", "Gafgyt-IRC-Kaiten"),
    ("0004b57f7671cb3dbc993e632279e883d138ea72a271b3ab84637c918e391023", "native_i386_static", "Gafgyt-plain"),
]
GUEST = "10.0.0.10"


def generate_selection():
    cases = []
    for sha, mode, fam in TARGETS:
        z = STUDY / COHORT / (sha + ".zip")
        require(z.is_file(), "missing cohort sample: " + sha)
        cases.append({"member_sha256": sha, "source_path": str(z.relative_to(STUDY)), "transport_ready": True,
                      "mode": mode, "family": fam, "split": "probe"})
    nulls = [{"mode": m, "spot": "start"} for m in ("native_amd64_static", "native_i386_static")]
    return {"cases": cases}, {"cases": [], "nulls": nulls}


def freeze():
    v21.verify_production()
    run_id = stamp()
    attempt = ROOT / "gafgyt-observe" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/gafgyt-observe-" + run_id
    sel, null_bind = generate_selection()
    save(attempt / "gafgyt_selection.json", sel)
    workdir = attempt / "_wrap"; workdir.mkdir()
    manifest, order = builder.build(attempt / "payload", sel, null_bind, guest_root, workdir)
    subprocess.run(["rm", "-rf", str(workdir)], check=False)
    payload_bytes = v21.make_tgz(attempt / "payload")
    (attempt / "payload.tgz").write_bytes(payload_bytes)
    setup = v21.build_setup(guest_root, payload_bytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    protocol = {
        "format": "c2-viability-probe-v1", "sample_set": "gafgyt-c2-observe", "schema": v21.SCHEMA,
        "production_hashes": v21.PINNED,
        "purpose": "PASSIVE observation of Gafgyt C2 handshakes against the isolated Sink; no controller, no flood "
                   "commanded; learn C2 endpoint/port/handshake to design the Phase-2 controller",
        "baseline_snapshot": v21.BASELINE, "baseline_uuid": v21.BASELINE_UUID, "original_uuid": v21.ORIGINAL_UUID,
        "new_snapshot": "clean-gafgyt-observe-" + run_id, "guest_root": guest_root, "settings": v21.SETTINGS,
        "cases": order, "counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
        "gafgyt_selection_sha256": digest(attempt / "gafgyt_selection.json"),
        "payload_sha256": digest(attempt / "payload.tgz"),
        "builder_sha256": digest(Path(builder.__file__)), "driver_sha256": digest(__file__),
        "approval": None, "vm_steps_authorized": [], "retries": False, "resume": False, "replacement": False,
        "files": {name: digest(attempt / name) for name in ("payload.tgz", "setup_guest.sh", "cases.txt")},
        "limitations": [
            "Passive observation only; bots dial their hardcoded C2 (-> the Sink) and idle; nothing is commanded.",
            "Guest is intnet-only (no route off malnet); target of any later flood will be the Sink only.",
            "A flood is host-loud too; the contribution is the Phase-5 benign-bulk comparison, not host-evasion."]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": digest(attempt / "protocol.json"),
                      "counts": protocol["counts"], "new_snapshot": protocol["new_snapshot"]}, indent=2))
    return attempt


def observe(attempt):
    attempt = Path(attempt)
    from scapy.all import rdpcap, TCP, UDP, IP, Raw   # noqa: E402
    protocol = load(attempt / "protocol.json")
    for case in protocol["cases"]:
        if case["label"] != "malware":
            continue
        d = attempt / "runs" / case["sample"]
        pcap = next(d.glob("output/run_*/packet_capture.pcap"), None)
        rj = next(d.glob("output/run_*/run.json"), None)
        meta = json.loads(rj.read_text()) if rj else {}
        te = meta.get("target_exec", {}) or {}
        print(f"\n=== {case['family']} ({case['sample'][:12]}) ===")
        print(f"  exec={te.get('status')} rc={meta.get('return_code')} "
              f"post_target_syscalls={te.get('post_target_lineage_raw_syscalls')}")
        if not pcap:
            print("  (no pcap)")
            continue
        pkts = rdpcap(str(pcap))
        syns, answered, payloads, udp = set(), set(), {}, collections.Counter()
        for p in pkts:
            if IP not in p:
                continue
            ip = p[IP]
            if TCP in p:
                t = p[TCP]
                if ip.src == GUEST and (t.flags & 0x02) and not (t.flags & 0x10):
                    syns.add((ip.dst, int(t.dport)))
                if ip.dst == GUEST and (int(t.flags) & 0x12) == 0x12:
                    answered.add((ip.src, int(t.sport)))
                if ip.src == GUEST and Raw in p:
                    payloads.setdefault((ip.dst, int(t.dport)), bytes(p[Raw].load)[:200])
            elif UDP in p and ip.src == GUEST:
                udp[(ip.dst, int(p[UDP].dport))] += 1
        print(f"  total frames={len(pkts)}")
        print(f"  TCP C2 dial attempts (dst:port): {sorted(syns)}")
        print(f"  peers that answered SYN-ACK:     {sorted(answered)}")
        for (dst, dp), pl in sorted(payloads.items()):
            print(f"  -> handshake to {dst}:{dp}: {pl!r}")
        if udp:
            print(f"  outbound UDP (dst:port -> count): {dict(udp.most_common(8))}")


def self_test():
    sel, null_bind = generate_selection()
    assert len(sel["cases"]) == 2 and {c["mode"] for c in sel["cases"]} == {"native_amd64_static", "native_i386_static"}
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        manifest, order = builder.build(td / "payload", sel, null_bind, "/home/csci/Downloads/gafgyt-test", td / "_w")
        assert manifest["counts"].get("malware") == 2 and manifest["counts"].get("null") == 2, manifest["counts"]
        assert len(order) == 4
        for c in order:
            assert (td / "payload/samples" / c["sample"]).is_file()
    print("self-test OK: 2 Gafgyt (amd64+i386) + 2 null, payload assembles")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--phase", choices=["preflight", "stage", "dry-run", "collect"])
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    p.add_argument("--observe", action="store_true")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.observe:
        observe(a.attempt)
    elif a.phase:
        base.perform_phase(Path(a.attempt), a.phase, a.protocol_sha256, a.approval)
    else:
        p.error("one of --self-test / --freeze-only / --phase / --observe required")


if __name__ == "__main__":
    main()
