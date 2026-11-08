"""Random access to the scenario archives inside a stored (uncompressed) Proton Drive bundle, and to
the recordings inside each scenario archive, without extracting anything to disk."""

import io
import struct
import zipfile


class SubFile(io.RawIOBase):
    """Read-only, seekable window [offset, offset + size) of an open binary file."""

    def __init__(self, f, offset, size, owner=None):
        self.f, self.offset, self.size, self.pos = f, offset, size, 0
        self.owner = owner  # keeps the outer ZipFile (and so the open file) alive

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, pos, whence=0):
        self.pos = {0: pos, 1: self.pos + pos, 2: self.size + pos}[whence]
        return self.pos

    def readinto(self, buffer):
        n = max(0, min(len(buffer), self.size - self.pos))
        self.f.seek(self.offset + self.pos)
        data = self.f.read(n)
        buffer[:len(data)] = data
        self.pos += len(data)
        return len(data)


def stored_member(outer, info):
    """SubFile over a stored member of an open ZipFile (no decompression needed)."""
    if info.compress_type != zipfile.ZIP_STORED:
        raise ValueError("%s is compressed" % info.filename)
    f = outer.fp
    f.seek(info.header_offset)
    header = f.read(30)
    name_len, extra_len = struct.unpack("<HH", header[26:30])
    return SubFile(f, info.header_offset + 30 + name_len + extra_len, info.file_size, owner=outer)


def scenario_archives(bundle_path):
    """Yield (name, ZipFile) for every scenario archive in the bundle. A single scenario archive (one
    whose members are the recordings themselves) is yielded as is, under its file name."""
    outer = zipfile.ZipFile(bundle_path)
    infos = outer.infolist()
    if not all(i.filename.endswith(".zip") and "/" not in i.filename for i in infos):
        yield bundle_path.rsplit("/", 1)[-1], outer
        return
    for info in infos:
        yield info.filename, zipfile.ZipFile(io.BufferedReader(stored_member(outer, info), 1 << 20))
