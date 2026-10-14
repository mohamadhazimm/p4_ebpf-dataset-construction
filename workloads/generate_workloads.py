#!/usr/bin/env python3
"""Generate deterministic benign workloads from official Ubuntu tools."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


FAMILIES = [
    ("bzip2", "compression", "bzip2"),
    ("coreutils", "file-operations", "coreutils"),
    ("curl", "http-client", "curl"),
    ("diffutils", "file-comparison", "diffutils"),
    ("file", "file-identification", "file"),
    ("findutils", "file-search", "findutils"),
    ("gawk", "text-processing", "gawk"),
    ("git", "version-control", "git"),
    ("grep", "text-search", "grep"),
    ("gzip", "compression", "gzip"),
    ("iproute2", "network-inspection", "iproute2"),
    ("jq", "json-processing", "jq"),
    ("less", "document-viewing", "less"),
    ("netcat-openbsd", "http-client", "netcat-openbsd"),
    ("openssh-client", "key-management", "openssh-client"),
    ("openssl", "crypto-file-processing", "openssl"),
    ("perl-base", "text-processing", "perl-base"),
    ("procps", "process-inspection", "procps"),
    ("psmisc", "process-inspection", "psmisc"),
    ("rsync", "file-copy", "rsync"),
    ("sed", "text-processing", "sed"),
    ("tar", "archive", "tar"),
    ("unzip", "archive", "unzip"),
    ("vim-tiny", "document-editing", "vim-tiny"),
    ("wget", "http-client", "wget"),
    ("xz-utils", "compression", "xz-utils"),
    ("zip", "archive", "zip"),
    ("zstd", "compression", "zstd"),
]


TASKS = {
    "bzip2": 'bzip2 -c "$WORK/data/text.txt" > "$WORK/output/data.bz2"\nbzip2 -dc "$WORK/output/data.bz2" > "$WORK/output/restored.txt"\ncmp "$WORK/data/text.txt" "$WORK/output/restored.txt"',
    "coreutils": 'mkdir -p "$WORK/output/copy"\ncp -a "$WORK/data/." "$WORK/output/copy/"\nsha256sum "$WORK/output/copy/text.txt" > "$WORK/output/checksums.txt"\nsort "$WORK/data/records.txt" > "$WORK/output/sorted.txt"\nwc -l "$WORK/output/sorted.txt" > "$WORK/output/count.txt"',
    "curl": 'curl --noproxy "*" -fsS --max-time 5 "http://example.com/?case=$RUN_ID" -o "$WORK/output/http-body.txt"\ncurl --noproxy "*" -sSI --max-time 5 http://example.com/ > "$WORK/output/http-headers.txt"',
    "diffutils": 'diff -u "$WORK/data/records.txt" "$WORK/data/records-modified.txt" > "$WORK/output/diff.txt" || test "$?" -eq 1\ncmp -s "$WORK/data/text.txt" "$WORK/data/text.txt"',
    "file": 'file "$WORK/data/text.txt" "$WORK/data/payload.bin" "$WORK/data/records.json" > "$WORK/output/file-types.txt"',
    "findutils": 'find "$WORK/data" -type f -print0 | xargs -0 -r sha256sum > "$WORK/output/tree-checksums.txt"',
    "gawk": 'gawk -F, \'{ totals[$1] += $3; counts[$1]++ } END { for (key in totals) printf "%s,%d,%d\\n", key, counts[key], totals[key] }\' "$WORK/data/metrics.csv" | sort > "$WORK/output/summary.csv"',
    "git": 'git -C "$WORK/repo" init -q\ngit -C "$WORK/repo" config user.name "Benign Workload"\ngit -C "$WORK/repo" config user.email "benign@example.invalid"\ncp "$WORK/data/records.txt" "$WORK/repo/records.txt"\ngit -C "$WORK/repo" add records.txt\ngit -C "$WORK/repo" commit -qm "Add deterministic records"\nprintf "variant=%s\\n" "$RUN_ID" >> "$WORK/repo/records.txt"\ngit -C "$WORK/repo" diff --stat > "$WORK/output/git-diff.txt"\ngit -C "$WORK/repo" status --short > "$WORK/output/git-status.txt"',
    "grep": 'grep -E "^(alpha|beta|gamma)," "$WORK/data/records.txt" > "$WORK/output/matches.txt"\ngrep -c "alpha" "$WORK/data/text.txt" > "$WORK/output/match-count.txt"',
    "gzip": 'gzip -c "$WORK/data/text.txt" > "$WORK/output/data.gz"\ngzip -dc "$WORK/output/data.gz" > "$WORK/output/restored.txt"\ncmp "$WORK/data/text.txt" "$WORK/output/restored.txt"',
    "iproute2": 'ip -brief address show > "$WORK/output/interfaces.txt"\nip route show > "$WORK/output/routes.txt"\nss -s > "$WORK/output/socket-summary.txt"',
    "jq": 'jq -c "{run: .run, count: (.items | length), total: ([.items[].value] | add)}" "$WORK/data/records.json" > "$WORK/output/summary.json"\njq -r ".items[].name" "$WORK/data/records.json" | sort > "$WORK/output/names.txt"',
    "less": 'TERM=dumb less -F -X -- "$WORK/data/text.txt" > "$WORK/output/viewed.txt" 2>/dev/null || true',
    "netcat-openbsd": 'printf "GET / HTTP/1.0\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n" | timeout 5 nc.openbsd -w 3 10.0.0.1 80 > "$WORK/output/nc-response.txt" || true',
    "openssh-client": 'ssh-keygen -q -t ed25519 -N "" -C "benign-$RUN_ID" -f "$WORK/output/test_key"',
    "openssl": 'openssl dgst -sha256 "$WORK/data/text.txt" > "$WORK/output/digest.txt"\nopenssl rand -out "$WORK/output/random.bin" 256\nopenssl enc -aes-256-ctr -salt -in "$WORK/data/payload.bin" -out "$WORK/output/encrypted.bin" -pass pass:benign-workload',
    "perl-base": 'perl -ne \'$lines++; $bytes += length($_); END { print "lines=$lines bytes=$bytes\\n" }\' "$WORK/data/text.txt" > "$WORK/output/perl-summary.txt"',
    "procps": 'ps -eo pid,ppid,comm --sort=comm > "$WORK/output/processes.txt"\nfree -b > "$WORK/output/memory.txt"\ntop -b -n 1 > "$WORK/output/top.txt"',
    "psmisc": 'pstree -p $$ > "$WORK/output/process-tree.txt"\nfuser "$WORK/data/text.txt" > "$WORK/output/file-users.txt" 2>&1 || true',
    "rsync": 'mkdir -p "$WORK/output/rsync-copy"\nrsync -a "$WORK/data/" "$WORK/output/rsync-copy/"\ndiff -qr "$WORK/data" "$WORK/output/rsync-copy" > "$WORK/output/rsync-check.txt"',
    "sed": 'sed -E "s/alpha/ALPHA/g; s/beta/BETA/g" "$WORK/data/text.txt" > "$WORK/output/transformed.txt"',
    "tar": 'tar -czf "$WORK/output/data.tar.gz" -C "$WORK/data" .\nmkdir -p "$WORK/output/unpacked"\ntar -xzf "$WORK/output/data.tar.gz" -C "$WORK/output/unpacked"\nfind "$WORK/output/unpacked" -type f | wc -l > "$WORK/output/archive-count.txt"',
    "unzip": 'cd "$WORK/data"\nzip -q "$WORK/output/data.zip" text.txt records.json records.txt\nunzip -tq "$WORK/output/data.zip"\nmkdir -p "$WORK/output/unpacked"\nunzip -oq "$WORK/output/data.zip" -d "$WORK/output/unpacked"',
    "vim-tiny": 'cp "$WORK/data/text.txt" "$WORK/output/edited.txt"\nvim.tiny -Nu NONE -n -i NONE -es -c "s/alpha/ALPHA/g" -c "wq" "$WORK/output/edited.txt"',
    "wget": 'wget --no-proxy -q -T 5 -O "$WORK/output/wget-body.txt" "http://example.org/run/$RUN_ID"',
    "xz-utils": 'xz -c "$WORK/data/text.txt" > "$WORK/output/data.xz"\nxz -dc "$WORK/output/data.xz" > "$WORK/output/restored.txt"\ncmp "$WORK/data/text.txt" "$WORK/output/restored.txt"',
    "zip": 'cd "$WORK/data"\nzip -q "$WORK/output/data.zip" text.txt records.json records.txt\nzip -Tq "$WORK/output/data.zip"',
    "zstd": 'zstd -q -f "$WORK/data/text.txt" -o "$WORK/output/data.zst"\nzstd -q -d -f "$WORK/output/data.zst" -o "$WORK/output/restored.txt"\ncmp "$WORK/data/text.txt" "$WORK/output/restored.txt"',
}


READ_ONLY_TASKS = {
    "bzip2": 'bzip2 -c "$WORK/data/text.txt" > /dev/null',
    "coreutils": 'sha256sum "$WORK/data/records.txt" > /dev/null\nsort "$WORK/data/records.txt" > /dev/null\nwc -l "$WORK/data/records.txt" > /dev/null',
    "curl": 'curl --noproxy "*" -fsS --max-time 5 "http://example.com/?case=$RUN_ID" -o /dev/null\ncurl --noproxy "*" -sSI --max-time 5 http://example.com/ > /dev/null 2>&1',
    "diffutils": 'diff -u "$WORK/data/records.txt" "$WORK/data/records-modified.txt" > /dev/null || test "$?" -eq 1\ncmp -s "$WORK/data/text.txt" "$WORK/data/text.txt"',
    "file": 'file "$WORK/data/text.txt" "$WORK/data/payload.bin" "$WORK/data/records.json" > /dev/null',
    "findutils": 'find "$WORK/data" -type f -print0 | xargs -0 -r sha256sum > /dev/null',
    "gawk": 'gawk -F, \'{ totals[$1] += $3; counts[$1]++ } END { for (key in totals) printf "%s,%d,%d\\n", key, counts[key], totals[key] }\' "$WORK/data/metrics.csv" > /dev/null',
    "git": 'git diff --no-index --stat "$WORK/data/records.txt" "$WORK/data/records-modified.txt" > /dev/null || test "$?" -eq 1',
    "grep": 'grep -E "^(alpha|beta|gamma)," "$WORK/data/records.txt" > /dev/null\ngrep -c "alpha" "$WORK/data/text.txt" > /dev/null',
    "gzip": 'gzip -c "$WORK/data/text.txt" > /dev/null',
    "iproute2": 'ip -brief address show > /dev/null\nip route show > /dev/null\nss -s > /dev/null',
    "jq": 'jq -c "{run: .run, count: (.items | length), total: ([.items[].value] | add)}" "$WORK/data/records.json" > /dev/null',
    "less": 'TERM=dumb less -F -X -- "$WORK/data/text.txt" > /dev/null 2>&1 || true',
    "netcat-openbsd": 'printf "GET / HTTP/1.0\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n" | timeout 5 nc.openbsd -w 3 10.0.0.1 80 > /dev/null || true',
    "openssh-client": 'ssh-keygen -? > /dev/null 2>&1 || true',
    "openssl": 'openssl dgst -sha256 "$WORK/data/text.txt" > /dev/null\nopenssl enc -aes-256-ctr -salt -in "$WORK/data/payload.bin" -out /dev/null -pass pass:benign-workload',
    "perl-base": 'perl -ne \'$lines++; $bytes += length($_); END { print "lines=$lines bytes=$bytes\\n" }\' "$WORK/data/text.txt" > /dev/null',
    "procps": 'ps -eo pid,ppid,comm --sort=comm > /dev/null\nfree -b > /dev/null\ntop -b -n 1 > /dev/null',
    "psmisc": 'pstree -p $$ > /dev/null\nfuser "$WORK/data/text.txt" > /dev/null 2>&1 || true',
    "rsync": 'rsync -an "$WORK/data/" "$WORK/output/rsync-copy/" > /dev/null',
    "sed": 'sed -E "s/alpha/ALPHA/g; s/beta/BETA/g" "$WORK/data/text.txt" > /dev/null',
    "tar": 'tar -czf /dev/null -C "$WORK/data" .',
    "unzip": 'unzip -tq "$WORK/data/fixture.zip" > /dev/null',
    "vim-tiny": 'vim.tiny -Nu NONE -n -i NONE -es -c "q!" "$WORK/data/text.txt"',
    "wget": 'wget --no-proxy -q -T 5 -O /dev/null "http://example.org/run/$RUN_ID"',
    "xz-utils": 'xz -c "$WORK/data/text.txt" > /dev/null',
    "zip": 'zip -Tq "$WORK/data/fixture.zip" > /dev/null',
    "zstd": 'zstd -q -c "$WORK/data/text.txt" > /dev/null',
}


def make_fixture_files(root: Path, variant: int) -> None:
    root.mkdir(parents=True)
    items = []
    lines = []
    for index in range(80 + variant * 7):
        category = ("alpha", "beta", "gamma", "delta")[index % 4]
        value = (index * 17 + variant * 31) % 997
        name = f"item-{variant:03d}-{index:04d}"
        items.append({"name": name, "category": category, "value": value})
        lines.append(f"{category},{name},{value}")
    (root / "records.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (root / "records-modified.txt").write_text(
        "\n".join(lines[:-1] + [lines[-1] + ",changed"]) + "\n", encoding="utf-8"
    )
    (root / "text.txt").write_text(
        "\n".join(
            f"{item['category']} {item['name']} value={item['value']} alpha beta"
            for item in items
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "records.json").write_text(
        json.dumps({"run": variant, "items": items}, sort_keys=True), encoding="utf-8"
    )
    (root / "metrics.csv").write_text(
        "\n".join(f"{item['category']},{item['name']},{item['value']}" for item in items)
        + "\n",
        encoding="utf-8",
    )
    (root / "payload.bin").write_bytes(
        bytes((index * 37 + variant) % 256 for index in range(4096 + variant * 64))
    )
    nested = root / "nested"
    nested.mkdir()
    (nested / "notes.txt").write_text(
        "local benign document\n" * (3 + variant), encoding="utf-8"
    )
    with ZipFile(root / "fixture.zip", "w", ZIP_DEFLATED) as archive:
        for filename in ("text.txt", "records.json", "records.txt"):
            archive.write(root / filename, filename)


def make_fixture_script(
    variant: int,
    package_root: str,
    fixture_data: str,
    task: str,
    file_activity_mode: str,
    sink_download: bool,
) -> str:
    task = task.replace("$WORK/data", "$FIXTURE_DATA")
    setup = 'mkdir -p "$HOME" "$TMPDIR"'
    if file_activity_mode != "read-only":
        setup += ' "$PWD/work/output" "$PWD/work/repo"'
    if file_activity_mode == "multi-write":
        task = 'mkdir -p "$WORK/output/copied-fixtures"\ncp -a "$FIXTURE_DATA/." "$WORK/output/copied-fixtures/"\n' + task
    if sink_download:
        task += '\ncurl --noproxy "*" -fsS --max-time 5 "http://example.com/benign/$RUN_ID" -o /dev/null'
    return f'''#!/bin/bash
set -euo pipefail
export LC_ALL=C
export TERM=dumb
PACKAGE_ROOT={package_root!r}
FIXTURE_DATA={fixture_data!r}
export PATH="$PACKAGE_ROOT/usr/bin:$PACKAGE_ROOT/usr/sbin:$PACKAGE_ROOT/bin:$PACKAGE_ROOT/sbin:$PATH"
export LD_LIBRARY_PATH="$PACKAGE_ROOT/usr/lib/x86_64-linux-gnu:$PACKAGE_ROOT/lib/x86_64-linux-gnu:${{LD_LIBRARY_PATH:-}}"
export HOME="$PWD/home"
export GIT_CONFIG_NOSYSTEM=1
export TMPDIR="$PWD/tmp"
{setup}
WORK="$PWD/work"
RUN_ID={variant}
{task}
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--package-manifest", type=Path, required=True)
    parser.add_argument("--count", type=int, default=138)
    parser.add_argument(
        "--guest-package-root",
        default="/home/csci/Downloads/hybrid-rf-study/package-root",
    )
    parser.add_argument(
        "--guest-fixture-root",
        default="/home/csci/Downloads/hybrid-rf-study/workload_fixtures",
    )
    args = parser.parse_args()
    if args.count < len(FAMILIES):
        parser.error(f"--count must be at least {len(FAMILIES)} to cover every family")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        parser.error(f"output directory is not empty: {args.output_dir}")
    if args.fixture_dir.exists() and any(args.fixture_dir.iterdir()):
        parser.error(f"fixture directory is not empty: {args.fixture_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.fixture_dir.mkdir(parents=True, exist_ok=True)

    with args.package_manifest.open(newline="", encoding="utf-8") as source:
        package_rows = {row["package"]: row for row in csv.DictReader(source)}
    missing_packages = sorted({package for package, _, _ in FAMILIES} - package_rows.keys())
    if missing_packages:
        parser.error(f"package manifest is missing: {', '.join(missing_packages)}")

    repetitions = [args.count // len(FAMILIES)] * len(FAMILIES)
    for index in range(args.count % len(FAMILIES)):
        repetitions[index] += 1

    rows = []
    run_index = 0
    for (package, family, _), repeat_count in zip(FAMILIES, repetitions, strict=True):
        for variant in range(1, repeat_count + 1):
            run_index += 1
            artifact = f"benign_{package}_{variant:02d}.sh"
            artifact_stem = Path(artifact).stem
            file_activity_mode = ("read-only", "light-write", "multi-write")[(run_index - 1) % 3]
            sink_download = run_index % 3 == 0
            fixture_path = args.fixture_dir / artifact_stem / "data"
            make_fixture_files(fixture_path, variant)
            guest_fixture_path = (
                Path(args.guest_fixture_root) / artifact_stem / "data"
            )
            script = make_fixture_script(
                variant,
                args.guest_package_root,
                str(guest_fixture_path),
                READ_ONLY_TASKS[package]
                if file_activity_mode == "read-only"
                else TASKS[package],
                file_activity_mode,
                sink_download,
            )
            script_path = args.output_dir / artifact
            script_path.write_text(script, encoding="utf-8")
            script_path.chmod(0o755)
            package_row = package_rows[package]
            rows.append(
                {
                    "sample_artifact": artifact,
                    "label": "benign",
                    "package": package,
                    "package_version": package_row["version"],
                    "workload_family": family,
                    "group_id": f"benign::{package}",
                    "file_activity_mode": file_activity_mode,
                    "controlled_sink_download": sink_download,
                    "variant": variant,
                    "run_index": run_index,
                    "sha256": hashlib.sha256(script.encode()).hexdigest(),
                    "source": package_row["source"],
                }
            )

    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    with args.manifest.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(
        json.dumps(
            {
                "workloads": len(rows),
                "families": len(FAMILIES),
                "output": str(args.output_dir),
                "fixtures": str(args.fixture_dir),
                "manifest": str(args.manifest),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())