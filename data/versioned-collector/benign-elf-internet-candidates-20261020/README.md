# Benign ELF Candidates: Ubuntu Noble

Downloaded 2026-10-20 from official Ubuntu 24.04 (Noble) amd64 package archives. Package SHA-256 values were checked against the corresponding Ubuntu package download pages. Packages were extracted for static inspection only; they were not installed or executed, and no VM was operated.

| Workload area | Package/version | Extracted ELF | Binary SHA-256 | Package SHA-256 |
| --- | --- | --- | --- | --- |
| Local database | `sqlite3` 3.45.1-1ubuntu2.8 | `extracted/sqlite3/usr/bin/sqlite3` | `04d261a472c6838700310da6c8abaec05534945c6fe1a2b3353e945313fc20b4` | `78493e56909614ec1d588c9fae1739a704d9e1a6ff65509b1f06c3e4d53ed0c3` |
| Media processing | `ffmpeg` 7:6.1.1-3ubuntu5 | `extracted/ffmpeg/usr/bin/ffmpeg` | `ed16af623947494a72e284b6eb8ff225f2da22b38b5d5069c2fd4b4ba3384e41` | `1a23baace5f2688a47e28119aedae6993cd638e6279a7227dfc52d9a337a1c17` |
| Compression | `zstd` 1.5.5+dfsg2-2build1 | `extracted/zstd/usr/bin/zstd` | `beede0fe43e2ff52c943576778d36fd0cc5136d0aa8a2a859e3455d4802ca56e` | `bb14385ff3d6df723a686778dc5f87849f720a0add261b5de9bcd4915a490b2a` |

Package archives are in `packages/`. Official package pages:

- https://packages.ubuntu.com/noble/amd64/sqlite3/download
- https://packages.ubuntu.com/noble/amd64/ffmpeg/download
- https://packages.ubuntu.com/noble/amd64/zstd/download

All three extracted files are dynamically linked x86-64 ELF executables. Their runtime dependencies are not bundled here; FFmpeg in particular requires many shared libraries. These are candidate workloads, not yet guest-ready payloads. Any later install or run should use the isolated Ubuntu 24.04 guest, resolve dependencies from trusted Ubuntu repositories, use only local fixtures or the internal Sink, and require separate authorization. No benchmark run or data collection was performed.
