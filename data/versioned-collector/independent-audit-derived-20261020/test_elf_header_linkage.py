#!/usr/bin/env python3
"""Synthetic-fixture tests for elf_header_linkage.parse_elf (no real samples)."""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_header_linkage import parse_elf  # noqa: E402


def elf64(e_type=2, machine=62, interp=None, needed=()):
    """Little-endian ELF64 with optional PT_INTERP and a PT_DYNAMIC whose strtab sits in one PT_LOAD."""
    strtab = b"\0" + b"".join(n.encode() + b"\0" for n in needed)
    interp_bytes = interp.encode() + b"\0" if interp else b""
    phnum = 1 + bool(interp) + bool(needed)
    phoff, ehsize = 64, 64
    data_off = phoff + 56 * phnum
    interp_off = data_off
    strtab_off = interp_off + len(interp_bytes)
    dyn_off = strtab_off + len(strtab)
    offsets, pos = [], 1
    for name in needed:
        offsets.append(pos)
        pos += len(name) + 1
    dyn = b"".join(struct.pack("<qQ", 1, o) for o in offsets)
    dyn += struct.pack("<qQ", 5, 0x400000 + strtab_off) + struct.pack("<qQ", 0, 0)
    total = dyn_off + (len(dyn) if needed else 0)
    head = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    head += struct.pack("<HHIQQQIHHHHHH", e_type, machine, 1, 0, phoff, 0, 0, ehsize, 56, phnum, 64, 0, 0)
    phdrs = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, total, total, 0x1000)
    if interp:
        phdrs += struct.pack("<IIQQQQQQ", 3, 4, interp_off, 0, 0, len(interp_bytes), len(interp_bytes), 1)
    if needed:
        phdrs += struct.pack("<IIQQQQQQ", 2, 6, dyn_off, 0, 0, len(dyn), len(dyn), 8)
    body = interp_bytes + strtab + (dyn if needed else b"")
    return head + phdrs + body


def elf32_big_static(machine=8):
    head = b"\x7fELF" + bytes([1, 2, 1]) + b"\0" * 9
    head += struct.pack(">HHIIIIIHHHHHH", 2, machine, 1, 0, 52, 0, 0, 52, 32, 1, 40, 0, 0)
    return head + struct.pack(">IIIIIIII", 1, 0, 0x400000, 0x400000, 84, 84, 5, 0x1000)


class ParseElfTests(unittest.TestCase):
    def test_dynamic_with_needed(self):
        out = parse_elf(elf64(interp="/lib64/ld-linux-x86-64.so.2", needed=("libc.so.6", "libm.so.6")))
        self.assertEqual(out["linkage"], "dynamic")
        self.assertEqual(out["interpreter"], "/lib64/ld-linux-x86-64.so.2")
        self.assertEqual(out["needed"], "libc.so.6;libm.so.6")
        self.assertEqual(out["machine"], "EM_X86_64")

    def test_static_exec(self):
        out = parse_elf(elf64())
        self.assertEqual((out["linkage"], out["interpreter"], out["needed"]), ("static", "", ""))

    def test_static_pie(self):
        self.assertEqual(parse_elf(elf64(e_type=3, needed=("libc.so.6",)))["linkage"], "static-pie")

    def test_big_endian_32bit_mips(self):
        out = parse_elf(elf32_big_static())
        self.assertEqual((out["machine"], out["elf_class"], out["endian"], out["linkage"]),
                         ("EM_MIPS", "32-bit", "big", "static"))

    def test_markers(self):
        out = parse_elf(elf64() + b"UPX!" + b"\xff Go buildinf:")
        self.assertTrue(out["upx_marker"] and out["go_marker"])

    def test_non_elf_and_truncated(self):
        self.assertEqual(parse_elf(b"#!/bin/sh\n" * 10)["parse_error"], "not_elf_or_truncated")
        bad = bytearray(elf64())
        bad[32:40] = struct.pack("<Q", 10_000)
        self.assertEqual(parse_elf(bytes(bad))["parse_error"], "truncated_program_headers")


if __name__ == "__main__":
    unittest.main()
