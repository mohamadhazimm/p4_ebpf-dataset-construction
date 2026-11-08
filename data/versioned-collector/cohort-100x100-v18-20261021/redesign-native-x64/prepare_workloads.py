#!/usr/bin/env python3
"""Prepare noninteractive workload inputs; never operate VMs or execute malware."""

from __future__ import annotations

import bz2
import hashlib
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
GUEST_ROOT = "/home/csci/Downloads/cohort-native-x64-v18-20261021"
WORK = GUEST_ROOT + "/workspace"


def profiles():
    text = WORK + "/input.txt"
    other = WORK + "/other.txt"
    obj = WORK + "/fixture.o"
    archive = WORK + "/fixture.a"
    zip_path = WORK + "/payload.zip"
    commands = {
        "cat": [text], "sort": [text], "uniq": [text], "wc": ["-lwc", text],
        "head": ["-n", "100", text], "tail": ["-n", "100", text],
        "cut": ["-d", " ", "-f", "1", text], "paste": [text, other],
        "od": ["-An", "-tx1", "-N", "256", text], "cksum": [text],
        "md5sum": [text], "sha256sum": [text], "base64": [text],
        "stat": [text], "ls": ["-l", WORK], "du": ["-s", WORK],
        "comm": [WORK + "/sorted-a.txt", WORK + "/sorted-b.txt"],
        "join": [WORK + "/sorted-a.txt", WORK + "/sorted-b.txt"],
        "split": ["-l", "100", text, "chunk-"], "cp": [text, "copied.txt"],
        "addr2line": ["-e", obj, "0x0"], "ar": ["t", archive],
        "as-new": ["-o", "assembled.o", WORK + "/fixture.S"],
        "cxxfilt": ["_ZN7Fixture5valueEv"],
        "elfedit": ["--output-osabi", "GNU", obj],
        "ld-new": ["-r", "-o", "linked.o", obj], "nm-new": [obj],
        "objcopy": [obj, "copied.o"], "objdump": ["-d", obj],
        "ranlib": [archive], "readelf": ["-a", obj], "size": [obj],
        "strings": ["-a", obj], "strip-new": ["-o", "stripped.o", obj],
        "hostname": [], "dnsdomainname": [],
        "logger": ["-t", "cohort-fixture", "benign local fixture message"],
        "traceroute": ["-I", "-m", "1", "-q", "1", "-w", "1", "10.0.0.1"],
        "ping": ["-n", "-c", "2", "10.0.0.1"],
        "ftp": ["-4", "-n", "-i", "-e", "127.0.0.1", "65015"],
        "inetd": ["-d", WORK + "/inetd.conf"],
        "telnet": ["-E", "10.0.0.1", "80"],
        "whois": ["-h", "127.0.0.1", "-p", "65014", "example.invalid"],
        "rcp": [text, "rcp-copy.txt"],
        "free": ["-b"], "pgrep": ["-a", "systemd"], "pidof": ["systemd"],
        "pscommand": ["-eo", "pid,ppid,comm"], "uptime": [],
        "vmstat": ["1", "2"], "w": [], "top": ["-b", "-n", "2", "-d", "1"],
        "pstree": ["-p"], "fuser": [text], "prtstat": ["1"],
        "find": [WORK, "-maxdepth", "2", "-type", "f"],
        "xargs": ["--arg-file", WORK + "/arguments.txt", "/usr/bin/wc", "-c"],
        "gzip": ["-c", text], "bzip2": ["-c", text],
        "bzip2recover": [WORK + "/payload.bz2"],
        "grep": ["-n", "alpha", text], "sed": ["s/alpha/ALPHA/g", text],
        "gawk": ["{count[$1]++} END {for (word in count) print word, count[word]}", text],
        "git": ["-C", WORK + "/repo.git", "fsck", "--full"],
        "git-daemon": ["--reuseaddr", "--export-all", "--listen=127.0.0.1", "--port=65013", WORK + "/repo.git"],
        "zip": ["-q", "output.zip", text], "zipnote": [zip_path],
        "zipsplit": ["-n", "8192", "-b", ".", zip_path],
        "unzip": ["-q", "-o", zip_path, "-d", "unzipped"],
        "unzipsfx": ["-q", "-o", "-d", "unzipped-sfx"],
        "cal": ["2026"], "column": ["-t", WORK + "/table.txt"],
        "hexdump": ["-C", "-n", "256", text],
        "look": ["alpha", WORK + "/dictionary.txt"], "rev": [text],
        "uuidgen": ["--random"],
        "uuidparse": ["12345678-1234-4234-8234-123456789abc"],
        "getopt": ["-o", "ab:", "--", "-a", "-b", "value", "operand"],
        "lsblk": ["-b"], "lscpu": [], "findmnt": ["--list"],
        "namei": ["-l", text], "whereis": ["sh"], "fincore": [text],
        "lslocks": [], "lsmem": [],
        "cmp": [text, other], "diff": ["-u", text, other],
        "diff3": [text, other, WORK + "/third.txt"], "sdiff": [text, other],
        "patch": ["--batch", "--input", WORK + "/fixture.patch", "--output", "patched.txt", WORK + "/patch-input.txt"],
        "curl": ["--noproxy", "*", "--max-time", "4", "--fail", "--output", "http-response.txt", "http://10.0.0.1/"],
        "wget": ["--no-proxy", "--timeout=4", "--tries=1", "--output-document=http-response.txt", "http://10.0.0.1/"],
        "rsync": ["-a", text, "rsync-copy.txt"],
        "jq": ["-c", ".items | map(.value) | add", WORK + "/input.json"],
        "less": ["-F", "-X", text], "xz": ["-c", text],
        "zstd": ["-q", "-c", text],
        "tar": ["-cf", "output.tar", "-C", WORK, "input.txt", "input.json"],
        "openssl": ["dgst", "-sha256", text],
    }
    files = {
        "split": ["chunk-*"], "cp": ["copied.txt"],
        "as-new": ["assembled.o"], "ld-new": ["linked.o"],
        "objcopy": ["copied.o"], "strip-new": ["stripped.o"],
        "rcp": ["rcp-copy.txt"], "zip": ["output.zip"],
        "zipsplit": ["*.zip"], "unzip": ["unzipped/input.txt"],
        "unzipsfx": ["unzipped-sfx/input.txt"], "patch": ["patched.txt"],
        "curl": ["http-response.txt"], "wget": ["http-response.txt"],
        "rsync": ["rsync-copy.txt"], "tar": ["output.tar"],
    }
    zero_output = {"elfedit", "ranlib", "logger", "fuser", "inetd", "git-daemon", "git", "dnsdomainname", "bzip2recover", "ftp"}
    empty_match = {"fuser", "pgrep", "pidof", "cmp", "diff", "diff3", "sdiff"}
    result = {}
    for program, arguments in commands.items():
        service = program in {"inetd", "git-daemon"}
        result[program] = {
            "arguments": arguments,
            "expected_returncodes": [0, 1] if program in empty_match else [0],
            "foreground_service": service,
            "network_case": program in {"traceroute", "ping", "ftp", "telnet", "whois", "curl", "wget"} or service,
            "output_globs": files.get(program, []),
            "require_stdout": program not in files and program not in zero_output and not service,
            "preflight_timeout_seconds": 8,
        }
    return result


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_fixtures(destination):
    destination.mkdir(parents=True, exist_ok=True)
    text = ("alpha 1\nbeta 2\ngamma 3\n" * 200).encode()
    inputs = {
        "input.txt": text,
        "other.txt": text.replace(b"beta 2", b"beta 4"),
        "third.txt": text.replace(b"gamma 3", b"gamma 5"),
        "sorted-a.txt": b"alpha 1\nbeta 2\ngamma 3\n",
        "sorted-b.txt": b"alpha 4\nbeta 5\ndelta 6\n",
        "dictionary.txt": b"alpha\nalphabet\nbeta\ngamma\n",
        "table.txt": b"name value\nalpha 1\nbeta 2\n",
        "input.json": json.dumps({"items": [{"value": 1}, {"value": 2}]}).encode(),
        "arguments.txt": (WORK + "/input.txt\n" + WORK + "/other.txt\n").encode(),
        "patch-input.txt": b"alpha\nbeta\ngamma\n",
        "fixture.patch": b"--- original\n+++ modified\n@@ -1,3 +1,3 @@\n alpha\n-beta\n+BETA\n gamma\n",
        "fixture.S": b".text\n.globl fixture_entry\nfixture_entry:\n xor %eax, %eax\n ret\n",
        "inetd.conf": b"127.0.0.1:65012 stream tcp nowait csci /bin/cat cat\n",
        "payload.bz2": bz2.compress(text),
    }
    for name, data in inputs.items():
        (destination / name).write_bytes(data)
    with zipfile.ZipFile(destination / "payload.zip", "w", compression=zipfile.ZIP_STORED) as output:
        member = zipfile.ZipInfo("input.txt", (2026, 10, 21, 0, 0, 0))
        output.writestr(member, text)
    subprocess.run(["/usr/bin/cc", "-c", str(destination / "fixture.S"), "-o", str(destination / "fixture.o")], check=True)
    subprocess.run(["/usr/bin/ar", "rcsD", str(destination / "fixture.a"), str(destination / "fixture.o")], check=True)
    subprocess.run(["/usr/bin/git", "init", "--bare", str(destination / "repo.git")], check=True, capture_output=True)


def main():
    identity_path = ROOT / "manifests/benign-executables.json"
    identities = json.loads(identity_path.read_text())["executables"]
    tasks = profiles()
    programs = {row["program"] for row in identities}
    if programs != set(tasks) or len(identities) != 100:
        raise ValueError(f"profile coverage differs: missing={programs - set(tasks)} extra={set(tasks) - programs}")
    payload = ROOT / "payload"
    seed = payload / "workspace-seed"
    make_fixtures(seed)
    cases = []
    for identity in identities:
        source = ROOT / identity["path"]
        if sha256(source) != identity["sha256"]:
            raise ValueError(f"executable changed: {source}")
        target = payload / "samples" / identity["program"]
        target.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        derived = identity["program"] == "unzipsfx"
        if derived:
            data += (seed / "payload.zip").read_bytes()
        target.write_bytes(data)
        target.chmod(0o755)
        sample = identity["program"]
        container_sha256 = None
        if zipfile.is_zipfile(target):
            sample += ".zip"
            container = payload / "samples" / sample
            with zipfile.ZipFile(container, "w", compression=zipfile.ZIP_DEFLATED) as output:
                member = zipfile.ZipInfo(identity["program"], (2026, 10, 21, 0, 0, 0))
                member.external_attr = 0o100755 << 16
                output.writestr(member, data)
            container_sha256 = sha256(container)
        profile = tasks[identity["program"]]
        arguments_path = payload / "arguments" / (sample + ".json")
        arguments_path.parent.mkdir(parents=True, exist_ok=True)
        arguments_path.write_text(json.dumps(profile["arguments"]) + "\n")
        cases.append({**identity, **profile, "sample": sample, "collection_container_sha256": container_sha256,
                      "guest_sample": GUEST_ROOT + "/samples/" + identity["program"],
                      "staged_sha256": sha256(target), "derived_zip_appended": derived})
    fixtures = {str(path.relative_to(payload)): sha256(path)
                for path in sorted(seed.rglob("*")) if path.is_file()}
    null_source = payload / "null_control.c"
    null_source.write_text("int main(void) { return 0; }\n")
    diagnostic_source = payload / "nss_diagnostic.c"
    diagnostic_source.write_text('''#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#ifdef __GLIBC__
extern int __nss_configure_lookup(const char *, const char *);
#endif
int main(int argc, char **arguments) {
    if (argc < 2) return 2;
#ifdef __GLIBC__
    if (argc > 2) {
        __nss_configure_lookup("protocols", "files");
        __nss_configure_lookup("services", "files");
        __nss_configure_lookup("passwd", "files");
    }
#endif
    if (strcmp(arguments[1], "protocols") == 0) printf("found=%d\\n", getprotobyname("icmp") != NULL);
    else if (strcmp(arguments[1], "services") == 0) printf("found=%d\\n", getservbyname("ftp", "tcp") != NULL);
    else if (strcmp(arguments[1], "passwd") == 0) printf("found=%d\\n", getpwuid(999999) != NULL);
    else return 2;
    return 0;
}
''')
    subprocess.run(["/usr/bin/cc", "-O2", "-static", str(diagnostic_source), "-o", str(payload / "nss-diagnostic")], check=True)
    nulls = []
    for mode in ("static", "dynamic"):
        target = payload / "samples" / ("null-" + mode + "-01")
        flags = ["-static"] if mode == "static" else []
        subprocess.run(["/usr/bin/cc", "-O2", *flags, str(null_source), "-o", str(target)], check=True)
        for repeat in range(1, 4):
            name = f"null-{mode}-{repeat:02d}"
            repeat_target = payload / "samples" / name
            if repeat_target != target:
                repeat_target.write_bytes(target.read_bytes())
                repeat_target.chmod(0o755)
            (payload / "arguments" / (name + ".json")).write_text("[]\n")
            nulls.append({"sample": name, "mode": mode, "sha256": sha256(repeat_target)})
    output = {
        "status": "profiles_prepared_guest_preflight_pending", "collection_ready": False,
        "guest_root": GUEST_ROOT, "stdin": "DEVNULL", "terminal": False,
        "identities_sha256": sha256(identity_path), "generator_sha256": sha256(Path(__file__)),
        "fixtures_sha256": fixtures, "cases": cases, "null_controls": nulls,
        "limitations": ["Activity tiers are not maliciousness or proof of delivery.",
                        "Bzip2recover and elfedit/ranlib write only in the reset, watched common workspace.",
                        "No profile is accepted until its guest execution and outcome checks pass."],
    }
    (ROOT / "manifests/benign-workloads.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    (payload / "workloads.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"profiles": len(cases), "fixtures": len(fixtures), "collection_ready": False}, indent=2))


if __name__ == "__main__":
    main()