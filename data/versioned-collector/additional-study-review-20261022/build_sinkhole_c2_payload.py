"""Payload for the sinkhole C2 experiment: 28 real C2/backdoor samples + 28 benign network clients + 3 null, 5 min each.

Experiment 1 of the advisor's "something with C2" request: rerun the C2 and backdoor samples with the Sink's passive
sinkhole on, so their connections to hard-coded C2 addresses open (and are logged) instead of going nowhere, and
measure them next to benign network clients that also contact outside addresses.

MALWARE (28), transports reused VERBATIM from the frozen viability payloads (AES zips; the leaf name is the member
SHA-256, re-checked in memory by the self-test; nothing is written to disk or executed on the host):
  c2-viability/20261025T142642347649Z    all 18: Sliver 8, Cobalt Strike 4, Meterpreter 4, Winnti 1, Merlin 1
  evasive-viability/20261025T151638248361Z Rekoobe 10 of 16 (cap 10 per family, as in the dataset rules: both
                                         amd64-static ones + the first 8 amd64-dynamic by SHA-256, outcome-blind).
  BPFDoor (4) is left out by design: it is passive (waits for a magic packet) and never connects out.
  By mode: amd64-static 11, amd64-dynamic 12, i386-static 5.

BENIGN (28), mode-matched 11/12/5, 7 programs, all builds that already ran in the guest (revision5 network builds
and the redesign dynamic builds, same SHA-256). Destinations are RFC 5737 documentation addresses or hostnames,
so every connection goes through the sinkhole like the malware's: ports 80/443 -> INetSim, 53 -> dnsmasq, every
other port -> the silent listener (it accepts and never replies). Hostnames are used only with the glibc builds
(the guest's glibc resolver is the tested path). Patterns cover what C2 samples do against a sinkhole:
  periodic successful polling (wget --wait, lowrate poll/dns), periodic check-ins that get silence (curl --retry
  against silent ports, lowrate keepalive), long silent holds after a hello (openssl s_client -ign_eof, git
  ls-remote git://, whois), timeouts (rsync), one-shot fetches (curl, openssl). Each argv was tested on the host
  against loopback stand-ins (2026-11-13). lowrate_gen only accepts 10.0.0.0/8, so it uses 10.200.0.x, which is
  outside the guest's /24 and routed via the Sink.
NULL (3): reused verbatim from the revision5 payload, one per mode.

Layout is the batch's: samples/<case>.zip + arguments/<case>.zip.json + fixtures/sinkholec2/... + cases.json.
No VM, no sample execution.
"""

import io
import json
import random
import shutil
import sys
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build_v21_payload as v21b                 # noqa: E402  plain_zip / sha256_bytes

STUDY = ROOT.parents[2]
C2_PAYLOAD = ROOT / "c2-viability/20261025T142642347649Z/payload"
EVASIVE_PAYLOAD = ROOT / "evasive-viability/20261025T151638248361Z/payload"
REV5_PAYLOAD = ROOT / "revision5-collection/20261025T100025568989Z/payload"
NULL_SAMPLES = {
    "native_amd64_static": "null-native_amd64_static-start.zip",
    "native_i386_static": "null-native_i386_static-start.zip",
    "native_amd64_dynamic": "null-native_amd64_dynamic-start.zip",
}
FAMILY_CAP = 10
EXCLUDED_FAMILIES = {"BPFDoor": "passive backdoor: waits for a magic packet, never connects out"}

_A64 = "data/versioned-collector/additional-study-review-20261022/amd64-network-builds/20261024T172720Z/bin/"
_I386 = "data/versioned-collector/additional-study-review-20261022/i386-network-builds/20261024T163419Z/bin/"
_DYN = "data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/payload/samples/"
_LOW = "data/versioned-collector/additional-study-review-20261022/lowrate_gen"
BINARIES = {  # (program, mode) -> path under STUDY; the dynamic ones are the revision5 builds (same SHA-256)
    ("wget", "native_amd64_static"): _A64 + "wget", ("curl", "native_amd64_static"): _A64 + "curl",
    ("openssl", "native_amd64_static"): _A64 + "openssl", ("lowrate", "native_amd64_static"): _LOW,
    ("wget", "native_amd64_dynamic"): _DYN + "wget", ("curl", "native_amd64_dynamic"): _DYN + "curl",
    ("openssl", "native_amd64_dynamic"): _DYN + "openssl", ("git", "native_amd64_dynamic"): _DYN + "git",
    ("rsync", "native_amd64_dynamic"): _DYN + "rsync",
    ("wget", "native_i386_static"): _I386 + "wget", ("curl", "native_i386_static"): _I386 + "curl",
    ("openssl", "native_i386_static"): _I386 + "openssl", ("whois", "native_i386_static"): _I386 + "whois",
}
EXEC_NAME = {"lowrate": "lowrate_gen"}

# Behaviour expectations, checked after collection (a report, not a gate). Window = 0.5 s, 600 windows.
# rc -15: still running at the 300 s cutoff (killed by the runner).
THROUGHOUT = {"pattern": "throughout", "rc": [0, 28, -15], "min_last_active": 480, "min_active": 8}
HOLD = {"pattern": "hold", "rc": [-15], "max_last_active": 60}
ONESHOT = {"pattern": "oneshot", "rc": [0], "max_last_active": 40}
JOB60 = {"pattern": "job60", "rc": [0], "min_last_active": 100, "max_last_active": 140, "min_active": 8}


def _rsync(seconds):  # rsync's I/O timeout fired after ~2x --timeout on the host test; allow 1x to 2x
    return {"pattern": "timeout%d" % seconds, "rc": [30], "min_last_active": int(0.8 * seconds),
            "max_last_active": 4 * seconds + 40}


def _urls(base, count):
    return "".join("%s/%d\n" % (base, i) for i in range(count))


def _retry(max_time, retries, delay, url, insecure=False):
    return ["-s" + ("k" if insecure else ""), "-o", "/dev/null", "--max-time", str(max_time), "--retry", str(retries),
            "--retry-delay", str(delay), "--retry-all-errors", url]


def _wget(wait, listname):
    return ["-q", "--wait=%d" % wait, "-O", "/dev/null", "-i", "{F:%s}" % listname]


S, D, I = "native_amd64_static", "native_amd64_dynamic", "native_i386_static"
# (variant, program, mode, argv template, fixtures {name: text}, expectation, destination note)
BENIGN = [
    # ---- amd64-static (11)
    ("wget-w5-ip", "wget", S, _wget(5, "a64-w5.txt"), {"a64-w5.txt": _urls("http://198.51.100.7/updates", 57)},
     THROUGHOUT, "198.51.100.7:80 -> INetSim"),
    ("wget-w15-ip", "wget", S, _wget(15, "a64-w15.txt"), {"a64-w15.txt": _urls("http://198.51.100.8/feed", 19)},
     THROUGHOUT, "198.51.100.8:80 -> INetSim"),
    ("wget-w30-ip", "wget", S, _wget(30, "a64-w30.txt"), {"a64-w30.txt": _urls("http://203.0.113.9/status", 10)},
     THROUGHOUT, "203.0.113.9:80 -> INetSim"),
    ("curl-retry-8080", "curl", S, _retry(5, 18, 10, "http://203.0.113.20:8080/api/v1/status"), {},
     THROUGHOUT, "203.0.113.20:8080 -> silent"),
    ("curl-retry-8443", "curl", S, _retry(10, 13, 10, "https://198.51.100.21:8443/", True), {},
     THROUGHOUT, "198.51.100.21:8443 -> silent"),
    ("curl-retry-5222", "curl", S, _retry(3, 27, 7, "http://192.0.2.22:5222/"), {},
     THROUGHOUT, "192.0.2.22:5222 -> silent"),
    ("openssl-hold-8443", "openssl", S, ["s_client", "-connect", "203.0.113.30:8443", "-ign_eof"], {},
     HOLD, "203.0.113.30:8443 -> silent"),
    ("openssl-oneshot-443", "openssl", S, ["s_client", "-connect", "198.51.100.31:443", "-servername",
                                           "updates.example.org"], {}, ONESHOT, "198.51.100.31:443 -> INetSim"),
    ("lowrate-poll", "lowrate", S, ["poll", "5000", "60000", "10.200.0.80", "80"], {}, JOB60, "10.200.0.80:80 -> INetSim"),
    ("lowrate-keepalive", "lowrate", S, ["keepalive", "6000", "60000", "10.200.0.22", "1883"], {}, JOB60,
     "10.200.0.22:1883 -> silent"),
    ("lowrate-dns", "lowrate", S, ["dns", "4000", "60000", "10.200.0.53"], {}, JOB60, "10.200.0.53:53 -> dnsmasq"),
    # ---- amd64-dynamic (12): the glibc builds; hostnames resolve through dnsmasq
    ("wget-w5-host", "wget", D, _wget(5, "dyn-w5.txt"), {"dyn-w5.txt": _urls("http://updates.example-cdn.net/pkg", 57)},
     THROUGHOUT, "hostname:80 -> INetSim"),
    ("wget-w20-host", "wget", D, _wget(20, "dyn-w20.txt"), {"dyn-w20.txt": _urls("http://telemetry.example.org/ping", 15)},
     THROUGHOUT, "hostname:80 -> INetSim"),
    ("wget-w10-ip", "wget", D, _wget(10, "dyn-w10.txt"), {"dyn-w10.txt": _urls("http://192.0.2.70/check", 29)},
     THROUGHOUT, "192.0.2.70:80 -> INetSim"),
    ("curl-retry-8080-host", "curl", D, _retry(5, 18, 10, "http://api.example-saas.com:8080/v2/heartbeat"), {},
     THROUGHOUT, "hostname:8080 -> silent"),
    ("curl-retry-9443", "curl", D, _retry(8, 13, 12, "https://203.0.113.23:9443/", True), {},
     THROUGHOUT, "203.0.113.23:9443 -> silent"),
    ("curl-oneshot-host", "curl", D, ["-sk", "-o", "/dev/null", "https://download.example.org/file.txt"], {},
     ONESHOT, "hostname:443 -> INetSim"),
    ("openssl-hold-993", "openssl", D, ["s_client", "-connect", "198.51.100.33:993", "-ign_eof"], {},
     HOLD, "198.51.100.33:993 -> silent"),
    ("openssl-oneshot-host", "openssl", D, ["s_client", "-connect", "mail.example.org:443", "-servername",
                                            "mail.example.org"], {}, ONESHOT, "hostname:443 -> INetSim"),
    ("git-hold-ip", "git", D, ["ls-remote", "git://203.0.113.94/project.git"], {}, HOLD, "203.0.113.94:9418 -> silent"),
    ("git-hold-host", "git", D, ["ls-remote", "git://git.example.org/tools/project.git"], {}, HOLD,
     "hostname:9418 -> silent"),
    ("rsync-timeout60", "rsync", D, ["--contimeout=10", "--timeout=60", "rsync://198.51.100.87/module/"], {},
     _rsync(60), "198.51.100.87:873 -> silent"),
    ("rsync-timeout120-host", "rsync", D, ["--contimeout=10", "--timeout=120", "rsync://mirror.example.org/pub/"], {},
     _rsync(120), "hostname:873 -> silent"),
    # ---- i386-static (5)
    ("wget-w10-ip", "wget", I, _wget(10, "i386-w10.txt"), {"i386-w10.txt": _urls("http://198.51.100.40/news", 29)},
     THROUGHOUT, "198.51.100.40:80 -> INetSim"),
    ("curl-retry-8000", "curl", I, _retry(5, 18, 10, "http://192.0.2.41:8000/"), {}, THROUGHOUT,
     "192.0.2.41:8000 -> silent"),
    ("openssl-hold-8883", "openssl", I, ["s_client", "-connect", "203.0.113.42:8883", "-ign_eof"], {}, HOLD,
     "203.0.113.42:8883 -> silent"),
    ("whois-hold-a", "whois", I, ["-h", "198.51.100.43", "example.org"], {}, HOLD, "198.51.100.43:43 -> silent"),
    ("whois-hold-b", "whois", I, ["-h", "192.0.2.43", "-p", "43", "10.20.30.0"], {}, HOLD, "192.0.2.43:43 -> silent"),
]


def select_malware():
    """All 18 C2 samples + Rekoobe capped at 10 (both static, then amd64-dynamic by SHA-256). Outcome-blind."""
    c2 = [c for c in json.loads((C2_PAYLOAD / "cases.json").read_text()) if c["label"] == "malware"]
    ev = [c for c in json.loads((EVASIVE_PAYLOAD / "cases.json").read_text()) if c["label"] == "malware"]
    chosen = [(c, C2_PAYLOAD) for c in sorted(c2, key=lambda c: c["sample"])]
    rekoobe = sorted((c for c in ev if c["family"] == "Rekoobe"), key=lambda c: (c["mode"] != S, c["sample"]))
    chosen += [(c, EVASIVE_PAYLOAD) for c in rekoobe[:FAMILY_CAP]]
    assert all(c["family"] in EXCLUDED_FAMILIES or c["family"] == "Rekoobe" for c in ev)
    return chosen


def _interleave(cases):
    """One null per mode first (quiet checkpoints), then malware and benign alternated under a fixed seed."""
    nulls = sorted((c for c in cases if c["label"] == "null"), key=lambda c: c["mode"])
    mal = sorted((c for c in cases if c["label"] == "malware"), key=lambda c: c["sample"])
    ben = sorted((c for c in cases if c["label"] == "benign"), key=lambda c: c["sample"])
    rng = random.Random(42)
    rng.shuffle(mal)
    rng.shuffle(ben)
    out = []
    for a, b in zip(mal, ben):
        out += [a, b]
    return nulls + out + mal[len(ben):] + ben[len(mal):]


def build(out_dir, guest_root):
    out = Path(out_dir)
    for sub in ("samples", "arguments", "fixtures/sinkholec2"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    manifest = {"samples": {}, "arguments": {}, "benign_binaries": {}}
    cases = []

    for case, source in select_malware():
        leaf = case["sample"]
        shutil.copyfile(source / "samples" / leaf, out / "samples" / leaf)
        shutil.copyfile(source / "arguments" / (leaf + ".json"), out / "arguments" / (leaf + ".json"))
        manifest["samples"][leaf] = v21b.sha256_bytes((out / "samples" / leaf).read_bytes())
        cases.append({"sample": leaf, "label": "malware", "mode": case["mode"], "network": None,
                      "family": case["family"], "expected_member_sha256": case["member_sha256"],
                      "source": str(source.parent.relative_to(ROOT))})

    fixroot = guest_root.rstrip("/") + "/fixtures/sinkholec2/"
    for variant, program, mode, argv, fixtures, expectation, note in BENIGN:
        for name, text in fixtures.items():
            (out / "fixtures/sinkholec2" / name).write_text(text)
        args = [fixroot + a[3:-1] if a.startswith("{F:") and a.endswith("}") else a for a in argv]
        binary = (STUDY / BINARIES[(program, mode)]).read_bytes()
        exec_name = EXEC_NAME.get(program, program)
        sample = "%s-%s-%s.zip" % (mode, program, variant)
        blob = v21b.plain_zip(exec_name, binary)
        (out / "samples" / sample).write_bytes(blob)
        (out / "arguments" / (sample + ".json")).write_text(json.dumps(args))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        manifest["benign_binaries"][sample] = {"program": program, "mode": mode, "binary": BINARIES[(program, mode)],
                                               "sha256": v21b.sha256_bytes(binary)}
        cases.append({"sample": sample, "label": "benign", "mode": mode, "network": True, "program": program,
                      "variant": variant, "destination": note, "expectation": expectation})

    for mode, sample in NULL_SAMPLES.items():
        shutil.copyfile(REV5_PAYLOAD / "samples" / sample, out / "samples" / sample)
        shutil.copyfile(REV5_PAYLOAD / "arguments" / (sample + ".json"), out / "arguments" / (sample + ".json"))
        manifest["samples"][sample] = v21b.sha256_bytes((out / "samples" / sample).read_bytes())
        cases.append({"sample": sample, "label": "null", "mode": mode, "network": False, "spot": "start"})

    for a in (out / "arguments").iterdir():
        manifest["arguments"][a.name] = v21b.sha256_bytes(a.read_bytes())
    order = _interleave(cases)
    for i, c in enumerate(order, 1):
        c["position"] = i
    (out / "cases.json").write_text(json.dumps(order, indent=2))
    (out / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    manifest["counts"] = dict(Counter(c["label"] for c in order))
    manifest["by_mode_label"] = {str(k): v for k, v in sorted(Counter((x["mode"], x["label"]) for x in order).items())}
    manifest["by_group"] = {k: v for k, v in sorted(Counter(c.get("family") or c.get("program") or "null"
                                                             for c in order).items())}
    (out / "payload_manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest, order


def elf_mode(data):
    """native_amd64_static / native_amd64_dynamic / native_i386_static from the ELF header and PT_INTERP."""
    assert data[:4] == b"\x7fELF", "not an ELF"
    bits64 = data[4] == 2
    machine = int.from_bytes(data[18:20], "little")
    phoff = int.from_bytes(data[32:40] if bits64 else data[28:32], "little")
    phentsize = int.from_bytes(data[54:56] if bits64 else data[42:44], "little")
    phnum = int.from_bytes(data[56:58] if bits64 else data[44:46], "little")
    interp = any(int.from_bytes(data[phoff + i * phentsize: phoff + i * phentsize + 4], "little") == 3
                 for i in range(phnum))
    if machine == 62 and bits64:
        return "native_amd64_dynamic" if interp else "native_amd64_static"
    if machine == 3 and not bits64 and not interp:
        return "native_i386_static"
    return "unsupported"


def self_test():
    import hashlib
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory(prefix="hazim-sinkholec2-") as d:
        manifest, order = build(Path(d) / "payload", "/home/csci/Downloads/sinkholec2-TEST")
        assert manifest["counts"] == {"malware": 28, "benign": 28, "null": 3}, manifest["counts"]
        assert len({c["sample"] for c in order}) == len(order) == 59, "duplicate samples"
        per_mode = Counter((c["mode"], c["label"]) for c in order if c["label"] != "null")
        for mode, n in ((S, 11), (D, 12), (I, 5)):
            assert per_mode[(mode, "malware")] == per_mode[(mode, "benign")] == n, (mode, per_mode)
        fam = Counter(c["family"] for c in order if c["label"] == "malware")
        assert max(fam.values()) <= FAMILY_CAP and "BPFDoor" not in fam, fam
        for c in order:
            blob = (Path(d) / "payload/samples" / c["sample"]).read_bytes()
            if c["label"] == "malware":   # AES member hash, extracted to memory only
                member = subprocess.run(["7z", "x", "-so", "-pinfected", str(Path(d) / "payload/samples" / c["sample"])],
                                        capture_output=True).stdout
                assert hashlib.sha256(member).hexdigest() == c["expected_member_sha256"], c["sample"]
            elif c["label"] == "benign":
                z = zipfile.ZipFile(io.BytesIO(blob))
                (name,) = z.namelist()
                data = z.read(name)
                assert elf_mode(data) == c["mode"], (c["sample"], elf_mode(data))
                args = json.loads((Path(d) / "payload/arguments" / (c["sample"] + ".json")).read_text())
                assert not any("{F:" in a for a in args), args
                for a in args:
                    if a.startswith("/home/csci/"):
                        assert a.startswith("/home/csci/Downloads/sinkholec2-TEST/fixtures/sinkholec2/"), a
                        assert (Path(d) / "payload/fixtures/sinkholec2" / Path(a).name).exists(), a
                assert "10.0.0.1" not in " ".join(args), ("benign must not target the Sink itself", args)
        groups = Counter(c["program"] for c in order if c["label"] == "benign")
        assert len(groups) == 7, groups
        print("PASS build_sinkhole_c2_payload: counts", manifest["counts"], "| groups", manifest["by_group"])
        print("by mode/label:", manifest["by_mode_label"])


if __name__ == "__main__":
    self_test()
