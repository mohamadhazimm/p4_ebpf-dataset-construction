#!/usr/bin/env python3
"""Run four hash-allowlisted benign tasks with exact, bounded outcome checks."""

import argparse
import concurrent.futures
import datetime
import hashlib
import io
import json
import os
import socket
import subprocess
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PREPARATION = ROOT / "remediation-preparation/20261022T122641888212Z"
PROJECTS = {"libarchive", "perl", "imagemagick", "netcat-openbsd"}
PINS = {
    "executables.json": "1f3bb04ff89f095d78b7b993020f198a24e110a453087bb3e0150e8d1c95ab44",
    "independent_verification.json": "8ea5c490cafeffd99c85d3ee3294db1f0fd3c76c1a522c2c6a0be9413fecbc45",
}
PERL_TASK = 'open(my $input,"<",$ARGV[0]) or die $!; while (<$input>) { /^item(\d{5})\|(\d{8})\n$/ or die "bad record"; printf "%05d:%d\n",$1,$2*3+11; } close($input) or die $!;'


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1048576), b""):
            checksum.update(block)
    return checksum.hexdigest()


def save(path, value):
    with path.open("x") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")


def expect(condition, message):
    if not condition:
        raise ValueError(message)


def ppm(data):
    position = 0
    tokens = []
    while len(tokens) < 4:
        while position < len(data) and data[position] in b" \t\r\n":
            position += 1
        if position < len(data) and data[position] == 35:
            position = data.index(b"\n", position) + 1
            continue
        start = position
        while position < len(data) and data[position] not in b" \t\r\n":
            position += 1
        expect(position > start, "Truncated PPM header")
        tokens.append(data[start:position])
    expect(tokens[0] == b"P6" and tokens[3] == b"255", "Unsupported PPM encoding")
    expect(position < len(data) and data[position] in b" \t\r\n", "Missing raster separator")
    width, height = int(tokens[1]), int(tokens[2])
    raster = data[position + 1:]
    expect(0 < width <= 128 and 0 < height <= 128 and len(raster) == width * height * 3, "Invalid PPM raster")
    return width, height, raster


def fixtures(directory):
    directory.mkdir()
    members = {"records.txt": b"bounded archive fixture\n" * 1024,
               "pixels.bin": bytes(range(256)) * 128}
    with tarfile.open(directory / "input.tar", "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content in members.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(content), 0o644, 1577836800
            archive.addfile(entry, io.BytesIO(content))
    (directory / "records.txt").write_bytes(b"".join(
        ("item%05d|%08d\n" % (index, index * 7 + 3)).encode() for index in range(4096)))
    width, height = 32, 24
    pixels = bytes(value for vertical in range(height) for horizontal in range(width)
                   for value in (horizontal * 7 % 256, vertical * 11 % 256, (horizontal + vertical) * 3 % 256))
    (directory / "image.ppm").write_bytes(b"P6\n32 24\n255\n" + pixels)
    (directory / "network.bin").write_bytes(bytes(range(256)) * 1024)
    return members, pixels


def command(binary, arguments, work, environment):
    result = subprocess.run([str(binary), *arguments], cwd=work, env=environment,
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=20, check=False)
    (work / "stdout.bin").write_bytes(result.stdout)
    (work / "stderr.txt").write_bytes(result.stderr)
    expect(result.returncode == 0, "Target returned " + str(result.returncode))
    return result


def serve(listener, payload):
    listener.settimeout(8)
    with listener.accept()[0] as connection:
        connection.settimeout(8)
        peer = connection.getpeername()
        expect(peer[0] == "127.0.0.1", "Unexpected fixture peer")
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        expect(connection.recv(1) == b"", "Unexpected target request bytes")
        return {"peer": list(peer), "sent_bytes": len(payload),
                "payload_sha256": hashlib.sha256(payload).hexdigest()}


def run_task(row, work, inputs, members, pixels, environment):
    work.mkdir()
    binary = Path(row["path"])
    project = row["project"]
    evidence = {}
    if project == "libarchive":
        extracted = work / "extracted"
        extracted.mkdir()
        arguments = ["-xf", str(inputs / "input.tar"), "-C", str(extracted)]
        result = command(binary, arguments, work, environment)
        expect({path.name for path in extracted.iterdir()} == set(members), "Unexpected archive outputs")
        for name, content in members.items():
            path = extracted / name
            expect(not path.is_symlink() and path.is_file() and path.read_bytes() == content, "Archive content mismatch")
        evidence["extracted_files"] = len(members)
    elif project == "perl":
        arguments = ["-e", PERL_TASK, str(inputs / "records.txt")]
        result = command(binary, arguments, work, environment)
        expected = b"".join(("%05d:%d\n" % (index, (index * 7 + 3) * 3 + 11)).encode() for index in range(4096))
        expect(result.stdout == expected, "Transformed records mismatch")
        evidence["records_verified"] = 4096
    elif project == "imagemagick":
        arguments = ["-limit", "memory", "32MiB", "-limit", "map", "32MiB", str(inputs / "image.ppm"), "-rotate", "90", "-depth", "8", "rotated.ppm"]
        result = command(binary, arguments, work, environment)
        width, height, raster = ppm((work / "rotated.ppm").read_bytes())
        expected = b"".join(pixels[((23 - horizontal) * 32 + vertical) * 3:((23 - horizontal) * 32 + vertical) * 3 + 3]
                            for vertical in range(32) for horizontal in range(24))
        expect((width, height) == (24, 32) and raster == expected, "Rotated pixels mismatch")
        evidence["pixels_verified"] = width * height
    elif project == "netcat-openbsd":
        payload = (inputs / "network.bin").read_bytes()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            endpoint = listener.getsockname()
            arguments = ["-4", "-n", "-N", "-w", "5", endpoint[0], str(endpoint[1])]
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                receipt = pool.submit(serve, listener, payload)
                result = command(binary, arguments, work, environment)
                evidence["sender_receipt"] = receipt.result(timeout=10)
            expect(result.stdout == payload, "Received network body mismatch")
            evidence["receiver_verified_bytes"] = len(result.stdout)
    else:
        raise ValueError("Unapproved project")
    evidence.update({"project": project, "executable_sha256": row["sha256"],
                     "arguments": arguments, "returncode": result.returncode,
                     "stdout_sha256": digest(work / "stdout.bin"),
                     "stderr_sha256": digest(work / "stderr.txt"), "status": "accepted"})
    return evidence


def run():
    for name, expected in PINS.items():
        expect(digest(PREPARATION / name) == expected, "Preparation input changed: " + name)
    rows = json.loads((PREPARATION / "executables.json").read_text())
    expect(len(rows) == 4 and {row["project"] for row in rows} == PROJECTS, "Unexpected approved identities")
    for row in rows:
        path = Path(row["path"])
        expect(not path.is_symlink() and digest(path) == row["sha256"], "Executable changed")
    attempt = ROOT / "remediation-workload-readiness" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt.mkdir(parents=True, exist_ok=False)
    members, pixels = fixtures(attempt / "inputs")
    input_hashes = {path.name: digest(path) for path in (attempt / "inputs").iterdir()}
    environment = dict(os.environ, LC_ALL="C", OMP_NUM_THREADS="1", HOME=str(attempt))
    for name in ("PERL5OPT", "PERL5LIB", "PERLLIB", "MAGICK_CONFIGURE_PATH", "MAGICK_HOME", "LD_PRELOAD"):
        environment.pop(name, None)
    protocol = {"schema": "remediation-workload-readiness-v1", "driver_sha256": digest(Path(__file__)),
                "preparation": str(PREPARATION), "identities": rows, "fixture_hashes": input_hashes,
                "order": [row["project"] for row in rows], "stdin": "DEVNULL", "timeout_seconds": 20,
                "network": "loopback-only TCP receive; fixture starts listening before target",
                "task_definitions": {"libarchive": "extract two data-only uncompressed archive members",
                                     "perl": "transform 4096 structured records",
                                     "imagemagick": "rotate 32x24 RGB image with exact 768-pixel reference",
                                     "netcat-openbsd": "receive and verify a 262144-byte TCP body"},
                "collection_ready": False, "vm_operations": 0, "model_fits": 0}
    save(attempt / "protocol.json", protocol)
    report = {"status": "running", "results": [], "collection_ready": False, "guest_validated": False}
    try:
        for row in rows:
            report["results"].append(run_task(row, attempt / row["project"], attempt / "inputs", members, pixels, environment))
        expect(input_hashes == {path.name: digest(path) for path in (attempt / "inputs").iterdir()}, "Input fixture changed")
        for row in rows:
            expect(digest(Path(row["path"])) == row["sha256"], "Executable changed during validation")
        report["status"] = "four_host_workloads_accepted_guest_and_sensor_pending"
    except Exception as error:
        report.update({"status": "failed_preserved", "error": str(error)})
        raise
    finally:
        save(attempt / "host_validation.json", report)
        print(attempt, flush=True)


def self_test():
    expect(ppm(b"P6\n# fixture\n1 1\n255\n\x0a\x20\x00") == (1, 1, b"\x0a\x20\x00"), "Raster whitespace corrupted")
    for invalid in (b"P6\n1 1\n255\n\x00", b"P3\n1 1\n255\n\x00\x00\x00", b"P6\n129 1\n255\n"):
        try:
            ppm(invalid)
        except ValueError:
            continue
        raise AssertionError("Invalid image accepted")
    with tempfile.TemporaryDirectory() as directory:
        inputs = Path(directory) / "inputs"
        members, pixels = fixtures(inputs)
        expect(len(pixels) == 32 * 24 * 3, "Invalid pixel fixture")
        with tarfile.open(inputs / "input.tar") as archive:
            expect(all(member.isfile() and member.name in members for member in archive.getmembers()), "Unsafe archive fixture")
    print("PASS: fixture and exact-outcome guards; no target executed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--run-host-checks", action="store_true")
    options = parser.parse_args()
    self_test() if options.self_test else run()