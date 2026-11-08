"""Quiet-guest ambient-traffic A/B experiment (benign-only, no samples, no runner change).

Phase A boots the unchanged clean baseline and captures boot-phase enp0s3 traffic. Phase B boots the
baseline again, disables the label-independent background sources found in every matched45 capture
(NetworkManager connectivity checks, chrony, avahi, cups-browsed) and saves the result as a NEW child
snapshot; the baseline is never modified. Phase C boots that child and repeats Phase A's capture exactly.
Each capture contains one bounded positive-control HTTP GET to the internal Sink.

Prospective criteria: C must recover its positive control and contain zero frames from the disabled
sources. Every remaining C frame is reported, not assumed to be ambient or sample traffic.
"""

import argparse
import collections
import fcntl
import hashlib
import json
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
GUEST_SCRIPT = ROOT / "quiet_guest.sh"
CAPTURE_SCRIPT = ROOT / "ambient_capture.sh"
CAPTURE_SECONDS = 240
CONTROL_AFTER_SECONDS = 60
DISABLED_SOURCES = {
    "networkmanager_connectivity": lambda f: "connectivity-check.ubuntu.com" in (f["dns_query"] + f["http_host"]),
    "chrony_ntp": lambda f: f["protocol"] == "NTP" or f["dns_query"] == "ntp-bootstrap.ubuntu.com"
                            or f["dns_query"].endswith("ntp.ubuntu.com"),
    "avahi_mdns": lambda f: f["protocol"] == "MDNS" and "_ipp" not in f["dns_query"],
    "cups_browsing": lambda f: "_ipp" in f["dns_query"],
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def save(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def frames(pcap):
    fields = ["frame.time_epoch", "_ws.col.Protocol", "ip.src", "ip.dst", "dns.qry.name", "dns.flags.response",
              "http.host", "http.request.uri", "http.response.code", "tcp.stream"]
    command = ["tshark", "-r", str(pcap), "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for field in fields:
        command += ["-e", field]
    output = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    result = []
    for line in output.splitlines():
        values = (line.split("\t") + [""] * len(fields))[:len(fields)]
        result.append({"epoch": float(values[0] or 0), "protocol": values[1], "src": values[2], "dst": values[3],
                       "dns_query": values[4], "dns_response": values[5] in ("1", "True"), "http_host": values[6],
                       "http_uri": values[7], "http_code": values[8], "tcp_stream": values[9]})
    return result


def attribute(parsed, control_path):
    """Label each frame with a disabled source, 'control' or None; a TCP stream inherits its matched label."""
    streams = {}
    for frame in parsed:
        label = "control" if control_path and frame["http_uri"] == control_path else next(
            (name for name, match in DISABLED_SOURCES.items() if match(frame)), None)
        if label and frame["tcp_stream"]:
            streams.setdefault(frame["tcp_stream"], label)
    labels = []
    for frame in parsed:
        label = streams.get(frame["tcp_stream"]) if frame["tcp_stream"] else None
        if label is None:
            label = "control" if control_path and frame["http_uri"] == control_path else next(
                (name for name, match in DISABLED_SOURCES.items() if match(frame)), None)
        labels.append(label)
    return labels


def summarize(pcap, control_path=None):
    parsed = frames(pcap)
    labels = attribute(parsed, control_path)
    sources = {name: labels.count(name) for name in DISABLED_SOURCES}
    control = [frame for frame, label in zip(parsed, labels) if label == "control" and frame["http_uri"] == control_path]
    responses = [frame for frame, label in zip(parsed, labels) if label == "control" and frame["http_code"]]
    remaining = collections.Counter()
    for frame, label in zip(parsed, labels):
        if label is not None:
            continue
        label = frame["protocol"]
        if frame["dns_query"]:
            label += " " + frame["dns_query"]
        elif frame["http_host"]:
            label += " " + frame["http_host"]
        remaining[label] += 1
    return {"frames": len(parsed), "disabled_source_frames": sources, "control_request_frames": len(control),
            "sink_http_response_frames": len(responses), "remaining_by_source": dict(remaining.most_common()),
            "first_epoch": parsed[0]["epoch"] if parsed else None, "last_epoch": parsed[-1]["epoch"] if parsed else None}


def evaluate(baseline, quiet):
    criteria = {
        "quiet_control_recovered": quiet["control_request_frames"] >= 1 and quiet["sink_http_response_frames"] >= 1,
        "baseline_control_recovered": baseline["control_request_frames"] >= 1,
        "quiet_disabled_sources_absent": all(count == 0 for count in quiet["disabled_source_frames"].values()),
        "baseline_disabled_sources_present": sum(baseline["disabled_source_frames"].values()) > 0,
    }
    return {"criteria": criteria, "accepted": all(criteria.values()),
            "frames_baseline": baseline["frames"], "frames_quiet": quiet["frames"]}


class Guest:
    def __init__(self, helper, attempt):
        self.helper, self.attempt = helper, attempt

    def run(self, auth, *command, timeout=120):
        response = self.helper.vbox("guestcontrol", self.helper.VM, "run", *auth, "--exe", command[0],
                                    "--wait-stdout", "--wait-stderr", "--timeout", str(timeout * 1000), "--",
                                    *command[1:], check=False)
        return response

    def boot(self, snapshot, phase, auth):
        import capture_liveness_v4
        self.helper.vbox("snapshot", self.helper.VM, "restore", snapshot)
        self.helper.isolated(self.helper.VM)
        directory = self.attempt / phase
        directory.mkdir()
        capture_liveness_v4.wait_guest(self.helper, auth, directory / "guest-login.log")
        return directory

    def stage_credential(self, auth, password_file, guest_root):
        require(self.run(auth, "/bin/mkdir", "-m", "700", guest_root).returncode == 0, "Guest root creation failed")
        self.helper.vbox("guestcontrol", self.helper.VM, "copyto", *auth, password_file, guest_root + "/.auth")
        require(self.run(auth, "/bin/chmod", "600", guest_root + "/.auth").returncode == 0, "Credential chmod failed")

    def poweroff(self, graceful):
        if graceful:
            self.helper.vbox("controlvm", self.helper.VM, "acpipowerbutton", check=False)
            for _ in range(60):
                if self.helper.vm_info(self.helper.VM)["VMState"] == '"poweroff"':
                    return "graceful"
                time.sleep(2)
        if self.helper.vm_info(self.helper.VM)["VMState"] != '"poweroff"':
            self.helper.vbox("controlvm", self.helper.VM, "poweroff")
        return "hard"


def capture_phase(guest, auth, password_file, snapshot, phase):
    directory = guest.boot(snapshot, phase, auth)
    guest_root = "/home/%s/hazim-ambient-%s" % (guest.helper.GUEST_USER, phase)
    control_path = "/hazim-quiet-control/%s/%s" % (phase, uuid.uuid4().hex)
    try:
        guest.stage_credential(auth, password_file, guest_root)
        guest.helper.vbox("guestcontrol", guest.helper.VM, "copyto", *auth, str(CAPTURE_SCRIPT), guest_root + "/ambient_capture.sh")
        response = guest.run(auth, "/bin/bash", guest_root + "/ambient_capture.sh", guest_root, str(CAPTURE_SECONDS),
                             str(CONTROL_AFTER_SECONDS), control_path, timeout=CAPTURE_SECONDS + 90)
        (directory / "capture.log").write_text(response.stdout + response.stderr)
        require(response.returncode == 0, "Guest capture script failed: " + phase)
        for name in ("ambient.pcap", "control.json", "tcpdump.log", "uptime-start.txt", "uptime-end.txt"):
            guest.helper.vbox("guestcontrol", guest.helper.VM, "copyfrom", *auth, guest_root + "/" + name, str(directory / name))
        require(guest.run(auth, "/usr/bin/test", "-e", guest_root + "/.auth").returncode != 0, "Credential not removed")
    finally:
        guest.poweroff(graceful=False)
    summary = summarize(directory / "ambient.pcap", control_path)
    summary.update(snapshot=snapshot, control_path=control_path, control=json.loads((directory / "control.json").read_text()),
                   uptime_start_seconds=float((directory / "uptime-start.txt").read_text()),
                   uptime_end_seconds=float((directory / "uptime-end.txt").read_text()),
                   pcap_sha256=digest(directory / "ambient.pcap"))
    save(directory / "summary.json", summary)
    return summary


def build_quiet_snapshot(guest, auth, password_file, new_snapshot):
    directory = guest.boot(guest.helper.BASELINE, "configure", auth)
    guest_root = "/home/%s/hazim-quiet-setup" % guest.helper.GUEST_USER
    graceful = None
    try:
        guest.stage_credential(auth, password_file, guest_root)
        guest.helper.vbox("guestcontrol", guest.helper.VM, "copyto", *auth, str(GUEST_SCRIPT), guest_root + "/quiet_guest.sh")
        response = guest.run(auth, "/bin/bash", "-c", "sudo -S -p '' /bin/bash %s/quiet_guest.sh < %s/.auth" % (guest_root, guest_root))
        (directory / "configure.log").write_text(response.stdout + response.stderr)
        require(response.returncode == 0, "Quiet configuration failed")
        receipt = json.loads(response.stdout.strip().splitlines()[-1])
        require(guest.run(auth, "/bin/rm", "-rf", "--", guest_root).returncode == 0, "Setup directory removal failed")
        require(guest.run(auth, "/usr/bin/test", "-e", guest_root).returncode != 0, "Credential/setup directory persisted")
        guest.run(auth, "/bin/sync")
    finally:
        graceful = guest.poweroff(graceful=True)
    guest.helper.vbox("snapshot", guest.helper.VM, "take", new_snapshot, "--description",
                      "Child of %s with NetworkManager connectivity check, chrony, avahi and cups-browsed disabled "
                      "(quiet_ambient.py). Benign configuration only; no runner or sample change." % guest.helper.BASELINE)
    receipt.update(poweroff=graceful, snapshot=new_snapshot, parent=guest.helper.BASELINE)
    units = receipt["units"]
    require(units["chrony.service"]["active"] != "active" and units["avahi-daemon.service"]["enabled"] == "masked"
            and units["cups-browsed.service"]["enabled"] == "masked", "Quiet configuration receipt differs")
    save(directory / "receipt.json", receipt)
    return receipt


def execute(approval):
    from export_original_sources import check_competitors, helper_module
    helper = helper_module()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = ROOT / "quiet-ambient" / stamp
    attempt.mkdir(parents=True)
    new_snapshot = "clean-quiet-ambient-" + stamp
    save(attempt / "protocol.json", {
        "approval": approval, "baseline_snapshot": helper.BASELINE, "new_snapshot": new_snapshot,
        "capture_seconds": CAPTURE_SECONDS, "control_after_seconds": CONTROL_AFTER_SECONDS,
        "disabled_sources": sorted(DISABLED_SOURCES), "source_hashes": {str(path): digest(path) for path in
                                                                     (Path(__file__), GUEST_SCRIPT, CAPTURE_SCRIPT)},
        "sample_executions": 0, "runner_changed": False, "baseline_modified": False,
        "criteria": "C recovers its positive control and has zero frames from disabled sources; all other C frames reported"})
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        helper.verify_production()
        check_competitors()
        before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
        require(before["guest"]["VMState"] == '"poweroff"' and before["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"'
                and before["sink"]["VMState"] == '"running"', "Need original TLS/off and isolated Sink/running")
        save(attempt / "initial_vm_state.json", before)
        guest = Guest(helper, attempt)
        try:
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-quiet-auth-") as password:
                Path(password.name).chmod(0o600)
                password.write(helper.credentials())
                password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                baseline = capture_phase(guest, auth, password.name, helper.BASELINE, "A-baseline")
                receipt = build_quiet_snapshot(guest, auth, password.name, new_snapshot)
                quiet = capture_phase(guest, auth, password.name, new_snapshot, "C-quiet")
            result = {"baseline": baseline, "quiet": quiet, "configuration": receipt, **evaluate(baseline, quiet)}
            save(attempt / "result.json", result)
        except BaseException as error:
            save(attempt / "failure.json", {"error": type(error).__name__ + ": " + str(error)})
            raise
        finally:
            if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
                helper.vbox("controlvm", helper.VM, "poweroff")
            helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
            final = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
            save(attempt / "final_vm_state.json", final)
            require(final["guest"]["VMState"] == '"poweroff"' and final["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"'
                    and final["sink"]["VMState"] == '"running"', "Cleanup differs")
            helper.verify_production()
    print(attempt)
    print(json.dumps({key: result[key] for key in ("accepted", "criteria", "frames_baseline", "frames_quiet")}, indent=2))
    return attempt


def preflight():
    from export_original_sources import check_competitors, helper_module
    helper = helper_module()
    helper.verify_production()
    check_competitors()
    state = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
    require(state["guest"]["VMState"] == '"poweroff"' and state["guest"]["CurrentSnapshotName"] == '"' + helper.ORIGINAL + '"'
            and state["sink"]["VMState"] == '"running"', "Need original TLS/off and isolated Sink/running")
    snapshots = helper.vbox("snapshot", helper.VM, "list", "--machinereadable").stdout
    require('"%s"' % helper.BASELINE in snapshots, "Clean baseline snapshot missing")


def self_test():
    for script in (GUEST_SCRIPT, CAPTURE_SCRIPT):
        subprocess.run(["bash", "-n", str(script)], check=True)
    text = GUEST_SCRIPT.read_text()
    commands = [line.split()[1] for line in text.splitlines() if line.strip().startswith("systemctl ") and len(line.split()) > 1]
    require(set(commands) <= {"disable", "mask"}, "Quiet script uses an unexpected systemctl verb")
    require("/etc/NetworkManager/conf.d/99-hazim-quiet-ambient.conf" in text and "rm " not in text, "Quiet script scope differs")
    require(".auth" in CAPTURE_SCRIPT.read_text() and "trap 'rm -f \"$auth\"' EXIT" in CAPTURE_SCRIPT.read_text(),
            "Capture script does not remove the credential")
    # Real saved V3 capture: every disabled source family is present before quieting.
    v3 = ROOT / "scoped-performance-v3/20261023T132643813743Z/evidence.tgz"
    with tempfile.TemporaryDirectory(prefix="hazim-quiet-selftest-") as directory:
        subprocess.run(["tar", "-xzf", str(v3), "-C", directory, "--wildcards", "output-case-001/*/packet_capture.pcap"], check=True)
        pcap = next(Path(directory).rglob("packet_capture.pcap"))
        summary = summarize(pcap)
    sources = summary["disabled_source_frames"]
    require(sources["networkmanager_connectivity"] > 0 and sources["chrony_ntp"] > 0 and sources["avahi_mdns"] > 0,
            "Classifier misses known ambient sources in a real capture: " + json.dumps(sources))
    quiet = {"frames": 2, "disabled_source_frames": {name: 0 for name in DISABLED_SOURCES}, "control_request_frames": 1,
             "sink_http_response_frames": 1}
    require(evaluate(summary | {"control_request_frames": 1}, quiet)["accepted"], "Quiet fixture rejected")
    require(not evaluate(summary | {"control_request_frames": 1}, quiet | {"control_request_frames": 0})["accepted"],
            "Missing positive control accepted")
    require(not evaluate(summary | {"control_request_frames": 1}, summary | {"control_request_frames": 1})["accepted"],
            "Unquieted capture accepted as quiet")
    print("PASS guest-script syntax/scope, credential removal, real-capture ambient classification "
          + json.dumps(sources) + " and criteria guards; no VM operation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--check-only", action="store_true")
    action.add_argument("--execute", action="store_true")
    parser.add_argument("--approval", help="verbatim user approval, required with --execute")
    options = parser.parse_args()
    sys.path.insert(0, str(ROOT))
    self_test()
    if options.self_test:
        return
    preflight()
    print("PASS read-only production/competitor/original-TLS/off/internal-only/Sink/baseline preflight")
    if options.execute:
        if not options.approval:
            parser.error("--execute requires --approval")
        execute(options.approval)


if __name__ == "__main__":
    main()
