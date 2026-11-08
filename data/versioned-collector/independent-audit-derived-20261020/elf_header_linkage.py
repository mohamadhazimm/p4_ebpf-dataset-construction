#!/usr/bin/env python3
"""DERIVED, EXPLORATORY, POST-HOC: static ELF-header linkage/architecture audit (2026-10-20).

Reads each scale-100x100 malware archive from the host copy with `7z x -so` (in memory only;
no ELF bytes are written to disk, made executable, or executed). Parses ELF headers, compares
them with the guest's recorded choice (chosen.txt / extract.log), and with the run-time libc
proxy in linkage.csv. Also flags qemu-user emulation from frozen event logs for all 300 runs.
Writes elf_header_linkage.csv and elf_header_linkage_results.json here.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import diagnostics as d  # noqa: E402

csv.field_size_limit(sys.maxsize)

EXPERIMENT = d.COLLECTOR / "scale-100x100-v14-20261020T072500Z"
MANIFEST = EXPERIMENT / "manifests" / "malware-100-completion.txt"
HOST_SAMPLES = d.STUDY / "data" / "malware" / "full-cohort-323" / "samples"
GUEST_EXTRACT = "/tmp/malware-lab/extracted/"
PASSWORD = "infected"
MAX_MEMBER_BYTES = 64 * 1024 * 1024
NATIVE = {"EM_X86_64", "EM_386"}
QEMU_MARKER = "/proc/sys/vm/mmap_min_addr"
MACHINES = {2: "EM_SPARC", 3: "EM_386", 4: "EM_68K", 8: "EM_MIPS", 10: "EM_MIPS_RS3_LE", 20: "EM_PPC",
            21: "EM_PPC64", 40: "EM_ARM", 42: "EM_SH", 43: "EM_SPARCV9", 62: "EM_X86_64",
            183: "EM_AARCH64", 243: "EM_RISCV"}
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB = 0, 1, 5


def parse_elf(data: bytes) -> dict:
    """Header-only ELF parse. Linkage: dynamic if PT_INTERP, else static/static-pie."""
    out = {"elf": data[:4] == b"\x7fELF", "parse_error": ""}
    if not out["elf"] or len(data) < 52:
        out["parse_error"] = "not_elf_or_truncated"
        return out
    cls, enc = data[4], data[5]
    if cls not in (1, 2) or enc not in (1, 2):
        out["parse_error"] = "bad_ident"
        return out
    e = "<" if enc == 1 else ">"
    is64 = cls == 2
    out.update(elf_class="64-bit" if is64 else "32-bit", endian="little" if enc == 1 else "big")
    e_type, e_machine = struct.unpack_from(e + "HH", data, 16)
    out["e_type"] = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, str(e_type))
    out["machine"] = MACHINES.get(e_machine, f"EM_{e_machine}")
    try:
        if is64:
            phoff, = struct.unpack_from(e + "Q", data, 32)
            phentsize, phnum = struct.unpack_from(e + "HH", data, 54)
        else:
            phoff, = struct.unpack_from(e + "I", data, 28)
            phentsize, phnum = struct.unpack_from(e + "HH", data, 42)
        phdrs = []
        for i in range(phnum):
            off = phoff + i * phentsize
            if is64:
                p_type, _f, p_off, p_vaddr, _pa, p_filesz = struct.unpack_from(e + "IIQQQQ", data, off)
            else:
                p_type, p_off, p_vaddr, _pa, p_filesz = struct.unpack_from(e + "IIIII", data, off)
            phdrs.append((p_type, p_off, p_vaddr, p_filesz))
    except struct.error:
        out["parse_error"] = "truncated_program_headers"
        return out
    interp = [p for p in phdrs if p[0] == PT_INTERP]
    dynamic = [p for p in phdrs if p[0] == PT_DYNAMIC]
    out["has_pt_interp"] = bool(interp)
    out["has_pt_dynamic"] = bool(dynamic)
    out["interpreter"] = (data[interp[0][1]:interp[0][1] + interp[0][3]].split(b"\0")[0]
                          .decode("latin-1") if interp else "")
    out["linkage"] = ("dynamic" if interp else
                      "static-pie" if out["e_type"] == "DYN" else "static")
    out["needed"] = ";".join(_needed(data, e, is64, phdrs, dynamic[0]) if dynamic else [])
    out["upx_marker"] = b"UPX!" in data
    out["go_marker"] = b"Go build ID" in data or b"\xff Go buildinf:" in data
    return out


def _needed(data, e, is64, phdrs, dyn) -> list[str]:
    size, fmt = (16, e + "qQ") if is64 else (8, e + "iI")
    tags = []
    for off in range(dyn[1], min(dyn[1] + dyn[3], len(data) - size + 1), size):
        tag, val = struct.unpack_from(fmt, data, off)
        if tag == DT_NULL:
            break
        tags.append((tag, val))
    strtab = next((v for t, v in tags if t == DT_STRTAB), None)
    base = _vaddr_to_offset(phdrs, strtab) if strtab is not None else None
    if base is None:
        return [f"<unresolved:{sum(t == DT_NEEDED for t, _ in tags)}>"] if tags else []
    names = []
    for tag, val in tags:
        if tag == DT_NEEDED and base + val < len(data):
            names.append(data[base + val:data.find(b"\0", base + val)].decode("latin-1"))
    return names


def _vaddr_to_offset(phdrs, vaddr):
    for p_type, p_off, p_vaddr, p_filesz in phdrs:
        if p_type == PT_LOAD and p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_off + (vaddr - p_vaddr)
    return None


def archive_members(zip_path: Path) -> list[dict]:
    listing = subprocess.run(["7z", "l", "-slt", f"-p{PASSWORD}", str(zip_path)],
                             capture_output=True, text=True, check=True).stdout
    body = listing.split("----------", 1)[1] if "----------" in listing else ""
    members = []
    for block in body.strip().split("\n\n"):
        fields = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
        if "Path" in fields and fields.get("Folder") != "+":
            members.append({"path": fields["Path"], "size": int(fields.get("Size") or 0)})
    return members


def read_member(zip_path: Path, member: str) -> bytes:
    data = subprocess.run(["7z", "x", "-so", f"-p{PASSWORD}", str(zip_path), member],
                          capture_output=True, check=True).stdout
    if len(data) > MAX_MEMBER_BYTES:
        raise ValueError(f"member exceeds cap: {zip_path.name}")
    return data


def guest_record(run_dir: Path) -> dict:
    chosen = dict(line.split("=", 1) for line in (run_dir / "chosen.txt").read_text().splitlines()
                  if "=" in line)
    log = (run_dir / "extract.log").read_text()
    archive = re.search(r"^1 file, (\d+) bytes", log, re.M)
    size = re.search(r"^Size:\s+(\d+)", log, re.M)
    return {"chosen": chosen.get("chosen_executable", ""), "guest_arch_field": chosen.get("sample_arch", ""),
            "guest_class_field": chosen.get("sample_elf_class", ""),
            "guest_archive_bytes": int(archive.group(1)) if archive else None,
            "guest_extracted_bytes": int(size.group(1)) if size else None}


def qemu_evidence(run_dir: Path) -> dict:
    """qemu-user reads /proc/sys/vm/mmap_min_addr at start; failure_reason may carry 'qemu:'."""
    meta = json.loads((run_dir / "run.json").read_text())
    root = meta["sample_root_pid"]
    with (run_dir / "syscall_events.csv").open(newline="") as handle:
        execs = [int(r["timestamp_ns"]) for r in csv.DictReader(handle)
                 if int(r["pid"]) == root and r["detail"] in ("id=59", "id=322")]
    boundary = execs[1] if len(execs) >= 2 else None
    marker = False
    if boundary is not None:
        with (run_dir / "ebpf_events.csv").open(newline="") as handle:
            marker = any(r["event"] == "openat" and int(r["timestamp_ns"]) > boundary
                         and QEMU_MARKER in r["detail"] for r in csv.DictReader(handle))
    return {"qemu_marker_after_exec": int(marker),
            "qemu_in_failure_reason": int("qemu:" in str(meta.get("failure_reason") or ""))}


def main() -> int:
    with (HERE / "run_audit.csv").open() as handle:
        audit = list(csv.DictReader(handle))
    with (HERE / "linkage.csv").open() as handle:
        proxy = {(r["cohort"], r["sample"]): r for r in csv.DictReader(handle)}
    run_dirs = {(r["cohort"], r["sample"]): d.COLLECTOR / r["run_dir"] for r in audit}
    samples = [s.strip() for s in MANIFEST.read_text().splitlines() if s.strip()]
    assert len(samples) == 100 and len(set(samples)) == 100

    qemu = {key: qemu_evidence(path) for key, path in run_dirs.items()}
    rows = []
    for sample in samples:
        run_dir = run_dirs[("malware", sample)]
        audit_row = next(r for r in audit if r["cohort"] == "malware" and r["sample"] == sample)
        zip_path = HOST_SAMPLES / sample
        guest = guest_record(run_dir.parents[1])
        members = archive_members(zip_path)
        rel = guest["chosen"].removeprefix(GUEST_EXTRACT)
        match = [m for m in members if m["path"] == rel]
        assert len(match) == 1, (sample, rel, members)
        data = read_member(zip_path, rel)
        header = parse_elf(data)
        sha = hashlib.sha256(data).hexdigest()
        del data
        stem = sample.removesuffix(".zip")
        link = proxy.get(("malware", sample))
        rows.append({
            "sample": sample, "group": audit_row["group"], "quality": audit_row["quality"],
            "return_code": audit_row["return_code"], "in_183_model": audit_row["in_183_model"],
            "archive_members": len(members), "member": rel,
            "host_zip_bytes": zip_path.stat().st_size, **guest,
            "member_bytes": match[0]["size"], "member_sha256": sha, "sha256_equals_name": int(sha == stem),
            **{k: header.get(k, "") for k in ("parse_error", "elf_class", "endian", "e_type", "machine",
                                              "has_pt_interp", "has_pt_dynamic", "interpreter",
                                              "linkage", "needed", "upx_marker", "go_marker")},
            "execution": "native" if header.get("machine") in NATIVE else "qemu_user",
            **qemu[("malware", sample)],
            "libc_proxy": link["libc_opened_after_exec"] if link else "",
        })
    with (HERE / "elf_header_linkage.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(summarise(rows, qemu, audit), indent=1))
    return 0


def summarise(rows, qemu, audit) -> dict:
    accepted = [r for r in rows if r["quality"] == "accepted"]
    out: dict = {"derived": True, "exploratory_post_hoc": True, "no_execution": True,
                 "source": "host archive copies streamed in memory via 7z -so; headers only"}
    out["identity_checks"] = {
        "single_member_archives": sum(r["archive_members"] == 1 for r in rows),
        "host_zip_bytes_equal_guest_log": sum(r["host_zip_bytes"] == r["guest_archive_bytes"] for r in rows),
        "member_bytes_equal_guest_log": sum(r["member_bytes"] == r["guest_extracted_bytes"] for r in rows),
        "machine_equals_guest_chosen": sum(r["machine"] == r["guest_arch_field"] for r in rows),
        "class_equals_guest_chosen": sum(r["elf_class"] == r["guest_class_field"] for r in rows),
        "member_sha256_equals_name": sum(r["sha256_equals_name"] for r in rows),
        "parse_errors": sum(bool(r["parse_error"]) for r in rows), "total": len(rows)}
    out["accepted_malware"] = len(accepted)
    out["by_machine"] = dict(Counter(r["machine"] for r in accepted).most_common())
    out["execution_x_header_linkage"] = dict(Counter(f"{r['execution']}|{r['linkage']}" for r in accepted).most_common())
    out["interpreters"] = dict(Counter(r["interpreter"] for r in accepted if r["interpreter"]).most_common())
    out["upx_marker"] = sum(bool(r["upx_marker"]) for r in accepted)
    out["go_marker"] = sum(bool(r["go_marker"]) for r in accepted)
    out["header_x_proxy"] = dict(Counter(f"{r['execution']}|{r['linkage']}|libc_proxy={r['libc_proxy']}"
                                         for r in accepted).most_common())
    out["qemu_marker_vs_header_execution"] = dict(Counter(
        f"{r['execution']}|marker={r['qemu_marker_after_exec']}" for r in accepted).most_common())
    out["qemu_marker_by_cohort"] = {c: dict(Counter(v["qemu_marker_after_exec"] for (cc, _), v in qemu.items()
                                                    if cc == c)) for c in ("malware", "benign_script", "benign_elf")}
    out["return_code_by_execution"] = {e: dict(Counter(r["return_code"] for r in accepted if r["execution"] == e)
                                               .most_common()) for e in ("native", "qemu_user")}
    out["proxy_discordant"] = [{k: r[k] for k in ("sample", "group", "machine", "linkage", "interpreter",
                                                    "libc_proxy", "return_code", "upx_marker")}
                               for r in accepted if (r["linkage"] == "dynamic") != (str(r["libc_proxy"]) == "1")]
    out["dynamic_header_samples"] = [{k: r[k] for k in ("sample", "group", "machine", "interpreter", "needed",
                                                          "libc_proxy", "return_code")}
                                     for r in accepted if r["linkage"] == "dynamic"]
    out["models"] = models(accepted)
    (HERE / "elf_header_linkage_results.json").write_text(json.dumps(out, indent=2) + "\n")
    return out


def models(accepted) -> dict:
    """Fixed rules (no fitting) and grouped OOF on header-defined strata, using diagnostics helpers."""
    with (HERE / "features_derived.csv").open() as handle:
        feats = {(r["cohort"], r["sample"]): r for r in csv.DictReader(handle)}
    header = {r["sample"]: r for r in accepted}
    rows = []
    for (cohort, sample), r in feats.items():
        r = dict(r, label=int(r["label"]))
        if cohort == "malware":
            r["execution"], r["linkage"] = header[sample]["execution"], header[sample]["linkage"]
        else:
            r["execution"], r["linkage"] = "native", "benign_unparsed"
        rows.append(r)

    def rule(subset, predicate):
        y = np.asarray([r["label"] for r in subset])
        return d.metrics(y, np.asarray([float(predicate(r)) for r in subset]),
                         np.asarray([r["group"] for r in subset]))

    s183 = [r for r in rows if r["in_183_model"] == "True"]
    b_all = [r for r in rows if r["cohort"] in ("malware", "benign_elf")]
    out = {"note": "benign artifacts are not on the host; benign linkage is the run-time proxy (all dynamic)",
           "rule_emulated_is_malware": {"S183": rule(s183, lambda r: r["execution"] == "qemu_user"),
                                        "B_all_accepted": rule(b_all, lambda r: r["execution"] == "qemu_user")},
           "rule_emulated_or_static_is_malware": {
               "S183": rule(s183, lambda r: r["execution"] == "qemu_user" or r["linkage"].startswith("static")),
               "B_all_accepted": rule(b_all, lambda r: r["execution"] == "qemu_user" or r["linkage"].startswith("static"))}}
    for name, keep in (("native_malware_vs_benign_elf", lambda r: r["execution"] == "native"),
                       ("native_dynamic_malware_vs_benign_elf",
                        lambda r: r["execution"] == "native" and r["linkage"] in ("dynamic", "benign_unparsed"))):
        subset = [r for r in b_all if keep(r)]
        y = np.asarray([r["label"] for r in subset])
        g = np.asarray([r["group"] for r in subset])
        block = {"samples": len(subset), "class_counts": dict(Counter(y.tolist())),
                 "groups_per_class": {c: len({gg for gg, yy in zip(g, y) if yy == c}) for c in (0, 1)}}
        if min(block["groups_per_class"].values()) >= 5:
            sp = d.splits_for(y, g)
            d.check_splits(y, g, sp)
            block["models"] = {n: d.metrics(y, d.oof(d.matrix(subset, cols), y, sp), g)
                               for n, cols in (("host_all", d.HOST), ("post_exec_host_all", d.POST),
                                               ("nuisance_only", d.NUISANCE))}
        else:
            block["models"] = "skipped: fewer than 5 groups in a class"
        out[name] = block
    return out


if __name__ == "__main__":
    raise SystemExit(main())
