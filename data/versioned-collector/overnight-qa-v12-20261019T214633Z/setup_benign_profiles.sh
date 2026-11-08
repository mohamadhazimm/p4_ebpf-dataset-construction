#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${BASH_SOURCE[0]}" != "/home/csci/.corrected-pilot-setup.sh" ]]; then
    exit 0
fi

exec /usr/bin/python3 - <<'PY'
import json
from pathlib import Path

base = Path("/home/csci/Downloads/paired-elf-watchpath-pilot-20261018")
benign_dir = base / "benign"
fixtures_dir = base / "fixtures"
watch_dir = base / "watch"
arguments_root = Path("/home/csci/Downloads/overnight-qa-benign-arguments")
tool_names = ("ping", "openssl", "vmstat", "tail", "md5sum", "dd", "find", "tar", "curl", "wget")

for tool_name in tool_names:
    executable = benign_dir / tool_name
    if not executable.is_file():
        raise FileNotFoundError(f"benign ELF control missing: {executable}")
if not (fixtures_dir / "payload.bin").is_file():
    raise FileNotFoundError(f"benign fixture missing: {fixtures_dir / 'payload.bin'}")
watch_dir.mkdir(parents=True, exist_ok=True)

ping_profiles = [
    ["-i", "0.5", "-w", "6", "10.0.0.1"],
    ["-i", "0.25", "-w", "6", "10.0.0.1"],
    ["-c", "10", "-W", "1", "10.0.0.1"],
    ["-i", "1", "-w", "6", "10.0.0.1"],
    ["-c", "5", "127.0.0.1"],
    ["-i", "0.4", "-w", "6", "10.0.0.1"],
    ["-c", "8", "-W", "1", "10.0.0.1"],
    ["-i", "0.75", "-w", "6", "10.0.0.1"],
    ["-c", "4", "127.0.0.1"],
    ["-i", "0.3", "-w", "6", "10.0.0.1"],
]
openssl_profiles = [
    ["speed", "-seconds", "6", "sha256"],
    ["speed", "-seconds", "6", "aes-128-cbc"],
    ["s_client", "-connect", "10.0.0.1:443", "-servername", "cdn.fwupd.org", "-brief", "-quiet"],
    ["speed", "-seconds", "6", "sha512"],
    ["speed", "-seconds", "6", "sha1"],
    ["s_client", "-connect", "10.0.0.1:443", "-servername", "cdn.fwupd.org", "-brief", "-quiet"],
    ["speed", "-seconds", "6", "aes-256-cbc"],
    ["speed", "-seconds", "6", "sha384"],
    ["s_client", "-connect", "10.0.0.1:443", "-servername", "cdn.fwupd.org", "-brief", "-quiet"],
    ["speed", "-seconds", "6", "sha256"],
]
vmstat_profiles = [["1", "7"], ["1", "8"], ["2", "4"], ["1", "6"], ["1", "9"],
                   ["1", "7"], ["2", "5"], ["1", "8"], ["1", "6"], ["2", "4"]]
tail_profiles = [["-f", "/dev/null"] for _ in range(10)]
md5_profiles = [
    ["/etc/passwd"], ["/etc/hosts"], [str(fixtures_dir / "payload.bin")],
    ["/usr/bin/curl"], ["/usr/bin/openssl"], ["/etc/group"],
    ["/usr/bin/wget"], [str(fixtures_dir / "payload.bin")],
    ["/etc/passwd", "/etc/hosts"], ["/usr/bin/ping"],
]
dd_profiles = [
    [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=64K", "status=none"],
    [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=16K", "status=none"],
    [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=4K", "status=none"],
    [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=128K", "status=none"],
    [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=32K", "status=none"],
    [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=8K", "status=none"],
    [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=64K", "count=16", "status=none"],
    [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=16K", "count=64", "status=none"],
    [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=32K", "count=32", "status=none"],
    [f"if={fixtures_dir / 'payload.bin'}", "of=/dev/null", "bs=4K", "count=128", "status=none"],
]
find_profiles = [
    ["/usr/share", "-xdev", "-type", "f", "-fprint", str(watch_dir / f"find-{index:02d}.txt")]
    for index in range(1, 11)
]
tar_profiles = [
    ["-cf", str(watch_dir / f"fixtures-{index:02d}.tar"), "-C", str(fixtures_dir), "."]
    if index % 2 else
    ["-czf", str(watch_dir / f"fixtures-{index:02d}.tar.gz"), "-C", str(fixtures_dir), "."]
    for index in range(1, 11)
]

def curl_http(path, extra=()):
    return ["--noproxy", "*", "-fsS", "--max-time", "6", "--resolve", "example.com:80:10.0.0.1", *extra,
            f"http://example.com/benign/{path}", "-o", "/dev/null"]


def curl_tls(path, extra=()):
    return ["--noproxy", "*", "--insecure", "-fsS", "--max-time", "6", "--resolve",
            "cdn.fwupd.org:443:10.0.0.1", *extra, f"https://cdn.fwupd.org/benign/{path}", "-o", "/dev/null"]


def wget_http(path, extra=()):
    return ["--no-proxy", "-q", "-T", "6", "-O", "/dev/null", *extra,
            f"http://10.0.0.1/benign/{path}"]


curl_profiles = [
    curl_http("pilot"),
    curl_http("profile-02"),
    curl_tls("profile-03"),
    curl_http("profile-04", ("-I",)),
    curl_http("profile-05", ("--range", "0-255")),
    curl_http("profile-06", ("-H", "X-Benign-Profile: 06")),
    curl_tls("profile-07", ("-I",)),
    curl_http("profile-08", ("--limit-rate", "16k")),
    curl_tls("profile-09", ("--range", "0-255")),
    curl_http("profile-10", ("-X", "HEAD")),
]
wget_profiles = [
    ["--no-proxy", "-q", "-T", "6", "-O", "/dev/null", "--header=Host: example.com",
     "http://10.0.0.1/benign/pilot"],
    wget_http("profile-02"),
    wget_http("profile-03", ("--header=Range: bytes=0-255",)),
    wget_http("profile-04", ("--spider",)),
    ["--no-proxy", "-q", "-T", "6", "-O", "/dev/null", "--no-check-certificate",
     "--header=Host: cdn.fwupd.org", "https://10.0.0.1/benign/profile-05"],
    wget_http("profile-06", ("--no-cache",)),
    wget_http("profile-07", ("--spider",)),
    wget_http("profile-08", ("--header=Range: bytes=0-511",)),
    ["--no-proxy", "-q", "-T", "6", "-O", "/dev/null", "--no-check-certificate",
     "--header=Host: cdn.fwupd.org", "https://10.0.0.1/benign/profile-09"],
    wget_http("profile-10"),
]

profiles = {
    f"profile-{index:02d}": {
        "ping": ping_profiles[index - 1],
        "openssl": openssl_profiles[index - 1],
        "vmstat": vmstat_profiles[index - 1],
        "tail": tail_profiles[index - 1],
        "md5sum": md5_profiles[index - 1],
        "dd": dd_profiles[index - 1],
        "find": find_profiles[index - 1],
        "tar": tar_profiles[index - 1],
        "curl": curl_profiles[index - 1],
        "wget": wget_profiles[index - 1],
    }
    for index in range(1, 11)
}

for profile_name, arguments_by_tool in profiles.items():
    profile_dir = arguments_root / profile_name
    profile_dir.mkdir(parents=True, exist_ok=True)
    if set(arguments_by_tool) != set(tool_names):
        raise RuntimeError(f"incomplete profile: {profile_name}")
    for tool_name, arguments in arguments_by_tool.items():
        if not all(isinstance(value, str) for value in arguments):
            raise TypeError(f"non-string argument in {profile_name}/{tool_name}")
        (profile_dir / f"{tool_name}.json").write_text(json.dumps(arguments) + "\n", encoding="utf-8")
PY

/usr/bin/python3 - <<'PY'
import json
from pathlib import Path

root = Path("/home/csci/Downloads/overnight-qa-benign-arguments")
tools = ("ping", "openssl", "vmstat", "tail", "md5sum", "dd", "find", "tar", "curl", "wget")
for profile_number in range(1, 11):
    profile = root / f"profile-{profile_number:02d}"
    for tool in tools:
        arguments = json.loads((profile / f"{tool}.json").read_text(encoding="utf-8"))
        if not isinstance(arguments, list) or not all(isinstance(value, str) for value in arguments):
            raise ValueError(f"invalid argument list: {profile}/{tool}.json")
PY

for profile in profile-01 profile-02 profile-03 profile-04 profile-05 profile-06 profile-07 profile-08 profile-09 profile-10; do
    for tool in ping openssl vmstat tail md5sum dd find tar curl wget; do
        test -s "/home/csci/Downloads/overnight-qa-benign-arguments/$profile/$tool.json"
    done
done
exit 0