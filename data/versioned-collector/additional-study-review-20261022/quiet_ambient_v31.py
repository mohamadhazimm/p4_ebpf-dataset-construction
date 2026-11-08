"""Quiet-v3.1: quiet-v3 with the guest-announcement spacing bound widened from 1.8-2.2 s to 1.5-3.0 s.

Evidence: the first headless boot (quiet-ambient-v3/20261024T135729274511Z, boot-01) contained only the guest's three
RFC 5227 conflict probes, three announcements, guest/Sink ARP and the HTTP control (no snapd, WS-Discovery or Sink
solicitation). It was rejected only because the announcement gaps were 2.003 s and 2.242 s, while the v2.3 allowance
required 1.8-2.2 s. The nominal interval is 2 s; the headless boot shows more timer jitter. The cap of three
announcements and every other field check are unchanged. Everything else is inherited from frozen quiet_ambient_v3.py.
"""

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import quiet_ambient_v3 as v3  # noqa: E402

v23, v22, v21, base, frozen, network, traffic = v3.v23, v3.v22, v3.v21, v3.base, v3.frozen, v3.network, v3.traffic
V3_SHA256 = "ead8e03ab2efac0554b957662207569c0255bbdc3da7ab4aa55f590e4c04e465"
FORMAT = "quiet-v3.1-multiboot-v1"
GAP_MIN_NS, GAP_MAX_NS = 1_500_000_000, 3_000_000_000
frozen_link_up_labels = v23.link_up_labels


def announcements(parsed, guest_mac):
    return [(index, packet) for index, packet in enumerate(parsed, 1)
            if (arp := v23.arp_fields(packet)) and arp["psrc"] == arp["pdst"] == traffic.GUEST]


def link_up_labels(parsed, guest_mac=v23.GUEST_MAC):
    """v2.3 link-up labels; only the announcement gap bound is replaced, all other bounds are v2.3's."""
    labels, reasons = frozen_link_up_labels(parsed, guest_mac)
    if "guest_announcements_outside_bounds" not in reasons:
        return labels, reasons
    found = announcements(parsed, guest_mac)
    times = [traffic.packet_ns(packet) for _index, packet in found]
    fields = [v23.arp_fields(packet) for _index, packet in found]
    common = all(arp["src"] == arp["hwsrc"] == guest_mac and arp["dst"] == v23.BROADCAST and arp["op"] == 1
                 and arp["hwdst"] == "00:00:00:00:00:00" and arp["ptype"] == 0x800 for arp in fields)
    gaps = [later - earlier for earlier, later in zip(times, times[1:])]
    if len(found) <= 3 and common and all(GAP_MIN_NS <= gap <= GAP_MAX_NS for gap in gaps):
        labels.update({index: "guest_self_announcement" for index, _packet in found})
        reasons = [reason for reason in reasons if reason != "guest_announcements_outside_bounds"]
    return labels, reasons


def check_frozen():
    v3.check_frozen()
    frozen.require(frozen.digest(v3.__file__) == V3_SHA256, "Frozen quiet-v3 driver changed")


def verify_plan(attempt, expected):
    frozen.require(expected and frozen.digest(attempt / "protocol.json") == expected, "Explicit protocol hash required")
    protocol = frozen.load(attempt / "protocol.json")
    frozen.require(protocol["format"] == FORMAT and protocol["boot_count"] == base.BOOT_COUNT
                   and protocol["capture_seconds"] == base.CAPTURE_SECONDS
                   and protocol["production_hashes"] == frozen.PINNED, "Protocol contract differs")
    check_frozen()
    frozen.verify_production()
    for name, checksum in protocol["source_hashes"].items():
        frozen.require(frozen.digest(name) == checksum, "Frozen source changed: " + name)
    for name, checksum in protocol["files"].items():
        frozen.require(frozen.digest(attempt / name) == checksum, "Frozen prepared artifact changed: " + name)
    return protocol


def freeze():
    check_frozen()
    frozen.verify_production()
    attempt = ROOT / "quiet-ambient-v3-1" / frozen.stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    plan = network.prepare(attempt / "controls")
    setup = frozen.setup_script(plan["guest_root"], (attempt / "controls/payload.tgz").read_bytes())
    setup = setup.replace("18 frozen transports", "14 benign-only transports")
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    ast.parse(setup.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0])
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(case["sample"] + "\n" for case in plan["cases"]))
    sources = frozen.source_hashes()
    for name in (__file__, v3.__file__, v23.__file__, v22.__file__, v21.__file__, base.__file__, network.__file__,
                 traffic.__file__, v3.POLICY, base.POLICY, ROOT / "quiet_ambient.py", ROOT / "capture_liveness_v4.py",
                 ROOT / "export_original_sources.py"):
        sources[str(Path(name).resolve())] = frozen.digest(name)
    files = {str(path.relative_to(attempt)): frozen.digest(path) for path in attempt.rglob("*") if path.is_file()}
    protocol = {"format": FORMAT,
        "derived_from": {"quiet_ambient_v3.py": V3_SHA256, "change": "announcement gap 1.5-3.0 s (was 1.8-2.2 s)",
                         "evidence": "quiet-ambient-v3/20261024T135729274511Z/phases/multiboot/boot-01 (gaps 2.003/2.242 s)",
                         "superseded_attempts": ["quiet-ambient-v2/20261024T110014475263Z",
                                                 "quiet-ambient-v2-1/20261024T132922140215Z",
                                                 "quiet-ambient-v2-2/20261024T133443341773Z",
                                                 "quiet-ambient-v2-3/20261024T134126526695Z",
                                                 "quiet-ambient-v3/20261024T135729274511Z"]},
        "policy": {"file": "quiet_guest_v3.sh", "sha256": frozen.digest(v3.POLICY), "default_target": "multi-user.target",
                   "snapd_masked_required": sorted(v3.SNAPD_REQUIRED), "headless_required_units": v3.HEADLESS_REQUIRED},
        "boot_count": base.BOOT_COUNT, "capture_seconds": base.CAPTURE_SECONDS, "production_hashes": frozen.PINNED,
        "baseline": frozen.BASELINE, "baseline_uuid": base.BASELINE_UUID, "original_uuid": base.ORIGINAL_UUID,
        "original_trace": v21.ORIGINAL_TRACE,
        "new_snapshot": "clean-final-quiet-v19-" + attempt.name,
        "staged_snapshot": "clean-final-quiet-v19-payload-" + attempt.name,
        "guest_mac": traffic.GUEST_MAC, "control_paths": ["/hazim-final/boot/" + attempt.name + "/" + str(index)
                                                       for index in range(1, base.BOOT_COUNT + 1)],
        "source_hashes": sources, "files": files, "approval": None, "vm_steps_authorized": [],
        "collection_ready": False, "retries": False, "model_fits": 0, "merge_with_v18": False,
        "merge_with_desktop_v19": False, "future_batch_cases": plan["cases"],
        "phases": ["preflight", "configure", "multiboot", "stage", "dry-run", "benign"],
        "allowances": ["VirtualBox 4-byte trace start record (record 1 only)",
                       "<=3 guest IPv4 conflict probes within 1 s, before the first announcement",
                       "<=3 guest announcements at 1.5-3.0 s spacing",
                       "<=3 Sink IPv6 router solicitations from the MAC answering ARP for 10.0.0.1"],
        "criteria": ["Policy receipt: quiet-v3, multi-user.target default, snapd + quiet-v2 units masked and inactive, "
                     "Guest Additions and NetworkManager pulled in by multi-user.target",
                     "Setup/credential directory absence positively confirmed by the guest before the snapshot",
                     "Ten traced 60 s boots, distinct boot IDs; every frame is the start record, a bounded link-up frame, "
                     "guest/Sink ARP or the marked HTTP control; anything else rejects",
                     "Every case in the later benign batch must independently pass the strict validator",
                     "Cleanup restores the original snapshot and trace off/none"],
        "limitations": ["Headless guest differs from the desktop guest used for all earlier captures; keep data separate",
                        "Hypervisor NIC tracing has no independent drop counter; not a completeness proof",
                        "Ten sixty-second boots do not exercise every later timer",
                        "No VM phase, batch, malware, fit or merge is authorized by preparation"]}
    frozen.save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": frozen.digest(attempt / "protocol.json"),
                      "vm_steps_authorized": [], "collection_ready": False}, indent=2))
    return attempt


def install():
    v3.install()
    check_frozen()
    v23.link_up_labels = link_up_labels  # v2.3 classify resolves link_up_labels through its module globals
    base.verify_plan = verify_plan


HEADLESS_BOOT = ROOT / "quiet-ambient-v3/20261024T135729274511Z/phases/multiboot/boot-01"
SNAPD_BOOT = ROOT / "quiet-ambient-v2-3/20261024T134126526695Z/phases/multiboot/boot-01"


def self_test():
    import shutil
    import struct
    import tempfile
    marker = frozen.load(HEADLESS_BOOT / "control.json")["path"]
    try:
        v23.audit_boot(HEADLESS_BOOT, marker)
        raise AssertionError("v2.3 bound unexpectedly accepted the headless boot")
    except ValueError as error:
        frozen.require("guest_announcements_outside_bounds" in str(error), "Headless boot rejected for another reason")
    v3.self_test()  # runs the inherited chain with the frozen bounds, then installs v3
    install()
    accepted = v23.audit_boot(HEADLESS_BOOT, marker)
    frozen.require(accepted["categories"] == {"hypervisor_trace_start_record": 1, "guest_ipv4_conflict_probe": 3,
                                              "guest_self_announcement": 3, "guest_sink_arp": 4, "declared_http": 12},
                   "Headless boot categories differ: %r" % accepted["categories"])
    print("PASS real headless boot-01 accepted with v3.1 bound:", accepted["categories"])
    try:
        v23.audit_boot(SNAPD_BOOT, frozen.load(SNAPD_BOOT / "control.json")["path"])
        raise AssertionError("snapd/WS-Discovery boot accepted")
    except ValueError:
        pass
    print("PASS real desktop boot with snapd + WS-Discovery still rejected")

    def shifted(third_gap_ns):
        records = v23.trace_records((HEADLESS_BOOT / "boot.pcap").read_bytes())
        is_announce = lambda data: data[12:14] == b"\x08\x06" and data[28:32] == data[38:42] == bytes([10, 0, 0, 10])
        indexes = [index for index, record in enumerate(records) if is_announce(record[3])]
        second = records[indexes[1]][0]
        moved = list(records)
        moved[indexes[2]] = (second + third_gap_ns // 1000, *records[indexes[2]][1:])
        moved.sort(key=lambda record: record[0])
        out = bytearray((HEADLESS_BOOT / "boot.pcap").read_bytes()[:24])
        for micros, _included, original, data in moved:
            out += struct.pack("<IIII", micros // 1_000_000, micros % 1_000_000, len(data), max(original, len(data))) + data
        directory = Path(tempfile.mkdtemp())
        for name in ("control.json", "trace.json"):
            shutil.copy(HEADLESS_BOOT / name, directory / name)
        (directory / "boot.pcap").write_bytes(bytes(out))
        try:
            v23.audit_boot(directory, marker)
            return True
        except ValueError:
            return False
        finally:
            shutil.rmtree(directory)
    outcomes = {gap: shifted(int(gap * 1e9)) for gap in (1.4, 1.6, 2.9, 3.1)}
    frozen.require(outcomes == {1.4: False, 1.6: True, 2.9: True, 3.1: False}, "Gap bounds wrong: %r" % outcomes)
    print("PASS announcement gap bound 1.5-3.0 s (1.4/3.1 rejected, 1.6/2.9 accepted)")
    frozen.require(v23.link_up_labels is link_up_labels and base.verify_plan is verify_plan and base.configure is v3.configure,
                   "Inherited phase machinery not routed through v3.1")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--audit-batch", action="store_true")
    action.add_argument("--phase", choices=("preflight", *base.PREDECESSOR))
    parser.add_argument("--attempt", type=Path)
    parser.add_argument("--protocol-sha256")
    parser.add_argument("--approval")
    options = parser.parse_args()
    if options.self_test:
        self_test()
        return
    if options.freeze_only:
        freeze()
        return
    install()
    frozen.require(options.attempt is not None, "Frozen attempt required")
    attempt = options.attempt.resolve()
    if options.audit_batch:
        base.audit_batch(attempt, verify_plan(attempt, options.protocol_sha256))
    else:
        base.perform_phase(attempt, options.phase, options.protocol_sha256, options.approval)


if __name__ == "__main__":
    main()
