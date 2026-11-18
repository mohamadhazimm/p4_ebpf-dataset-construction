# Benign programs rebuilt with the malware's toolchains (host-side, 2026-11-13)

Purpose: the host detector reads per-window system-call statistics, and the dataset's static benign programs (Ubuntu
22.04 glibc 2.35: `rseq`, `getrandom`, `set_robust_list`, `prlimit64` at start-up) start differently from the static
malware, which were built with other toolchains. Five yes/no start-up flags alone separate the classes. This folder
holds benign programs rebuilt with the same toolchain classes as the malware, host checks of them, a start-up
comparison against the malware's recorded start-ups, and a proposed case list. Nothing here was collected.

Scope kept: benign open-source software only; no VM operation; no sudo; no system package installed; nothing read
under `data/malware/` and no `*.zip` sample transport opened (the malware side comes only from the derived files
`../toolchain_classes.json` and `../startup_sequences.json`); no `.env` access; every download verified before use;
until 20:45 UTC all builds ran under `nice -n 19 taskset -c 12-23` with `-j6`/`-j8`. One side effect outside the folder
happened and was undone: printing `go version` of the freshly extracted Go 1.24 (before the build environment was set)
created `~/.config/go/telemetry` (local counters only, the directory did not exist before); it was deleted. All Go
builds ran with HOME/XDG/GOPATH/GOCACHE inside `gopath/`.

## Layout

| path | content |
|---|---|
| `scripts/` | everything used here (fetch, build, pack, check, compare, propose, manifest) |
| `downloads/<name>/` | downloaded files + `verification.json` (how each was verified) |
| `toolchains/` | extracted toolchains / sysroots |
| `sources/` | the dataset's own authenticated Ubuntu source packages, unpacked (`sources.json`), SQLite amalgamation |
| `builds/<toolchain>/` | build trees + `results.json`; `builds/upx-results.json` |
| `gobuild/` | Go module workdirs (go.mod/go.sum) + `results-<go>.json` |
| `bin/<toolchain>/<program>` | every produced binary |
| `checks/host_check-light.json` | host check of all 407 binaries (light bin) + start-up (first 50 calls) |
| `checks/startup_compare.json`, `.txt` | benign vs malware start-up comparison |
| `proposed_cases.json` | proposed case list (87 cases) incl. per-case host check at its bin |
| `manifest.json` | machine-readable: downloads, toolchains, sources, builds, every binary, cases |
| `logs/` | every fetch/build/check log |
| `probe/` | two tiny start-up probes (stdio, pthread) compiled against each sysroot to choose the old-glibc sysroots |

## 1. Toolchains obtained and how each was verified

| toolchain | what | source | verification |
|---|---|---|---|
| uClibc 0.9.30.1 + GCC 4.1.2 + binutils 2.17, `cross-compiler-x86_64` (22,268,113 B, sha256 `ff790a97d5ae7aea6126c9996b529ac57b99788f641607f519a9d4c57c8db138`) and `cross-compiler-i686` (21,118,703 B, sha256 `5282a7f9aaa896f2b47d0abdb5d5947e207d82a373c3732033ed7eab7b7a5e7d`) | the FWL/impactlinux cross-compilers uclibc.org published in 2009 under `downloads/binaries/0.9.30.1/` (the Mirai/Gafgyt build toolchain) | uclibc.org now answers 403 for both files and never published checksums; taken from the Wayback Machine (`id_` raw captures) | the SHA-1 of the copy equals the Wayback CDX content digest of every HTTP-200 capture of the official URL (x86_64: 6 captures 2010-2024, `LQ57CJ6EXRQXXWYANXQLOQLH2DDFGUBI`; i686: 4 captures 2010-2024, `MPQDSBHDOC7SKDAO2V4NEBAWPP4LLTMT`), and a 2010 and a 2024 capture were downloaded separately and are byte-identical. This is a consistency check against an independent archive, not a publisher signature (none exists). |
| glibc 2.17 static, CentOS 7.9.2009 x86_64 | glibc-devel/-static/-headers 2.17-317.el7, kernel-headers 3.10.0-1160.el7 | vault.centos.org | each RPM's embedded OpenPGP signatures (header+payload and header-only, RSA) checked with gpgv against `RPM-GPG-KEY-CentOS-7` whose fingerprint `6341AB2753D78A78A7C27BB124C6A8A7F4A80EB5` equals the one printed on https://www.centos.org/keys/; MD5/SHA1 digest tags recomputed; private GNUPGHOME |
| glibc 2.12 static, CentOS 6.10 i686 | glibc-devel/-static/-headers 2.12-1.212.el6, kernel-headers 2.6.32-754.el6 | vault.centos.org | same, key `C1DAC52D1664E8A4386DBA430946FCA2C105B9DE` |
| glibc 2.5 static, CentOS 5.11 i386 | glibc-devel (contains libc.a) and glibc-headers 2.5-123, kernel-headers 2.6.18-398.el5 | vault.centos.org | same, DSA key `473D66D5212271FD51CC17B1A8A447DCE8562897` |
| glibc 2.27 static, Ubuntu 18.04 | libc6-dev 2.27-3ubuntu1, linux-libc-dev 4.15.0-20.21 | archive.ubuntu.com | InRelease gpgv (Ubuntu archive keys 2012/2018 from the host keyring) -> SHA256 of Packages -> SHA256+size of each .deb; unpacked with `dpkg-deb -x` |
| glibc 2.31 static, Ubuntu 20.04 | libc6-dev 2.31-0ubuntu9, linux-libc-dev 5.4.0-26.30 | archive.ubuntu.com | same |
| glibc 2.23 static, Ubuntu 16.04 | libc6-dev 2.23-0ubuntu3, linux-libc-dev 4.4.0-21.37 | archive.ubuntu.com | same (2004 + 2012 keys); used only for a start-up probe |
| compiler for the old-glibc builds | host GCC 11.4.0 (Ubuntu 22.04) + binutils 2.38, `--sysroot` plus `-B/-L` to the sysroot (GCC's own install-relative paths otherwise win and the host libc.a is linked: caught by the first probe); i386: `-m32` + 32-bit libgcc | lib32gcc-11-dev 11.4.0-1ubuntu1~22.04.3 already in the workspace | deb sha256 `5bb9b32d...` listed in the jammy-updates main Packages whose hash is in the signed InRelease (gpgv good, 2018 key); copied files byte-identical to the package |
| Go 1.13.15, 1.16.15, 1.18.10, 1.20.14, 1.21.13, 1.22.12, 1.24.13 (linux-amd64) | official releases; builds use `GOARCH=amd64` and `386`, `CGO_ENABLED=0` | go.dev/dl | sha256 and size equal to the go.dev release index (`downloads/go/verification.json`) |
| Go modules (u-root, gojq, cespare/xxhash, ulikunitz/xz + deps) | | proxy.golang.org only (`GOPROXY` without `direct`) | the go command checked every module zip against the signed checksum database sum.golang.org (go.sum in `gobuild/`), `go mod verify` = "all modules verified" for all 28 workdirs; GOPATH/GOMODCACHE/GOCACHE/HOME/XDG dirs inside `gopath/`, `GOENV=off`, `GOTOOLCHAIN=local` |
| UPX 3.94 | upx-ucl 3.94-4 + libucl1 (Ubuntu 18.04) | archive.ubuntu.com | signed chain as above |
| UPX 4.2.2 | upx-ucl 4.2.2-3 + libucl1/libc6 2.39/libstdc++6/libgcc-s1/zlib1g (Ubuntu 24.04), run with noble's own loader | archive.ubuntu.com | signed chain as above |
| UPX 3.91, 3.95, 3.96 | upx-ucl from Ubuntu 16.04/20.04/22.04 | archive.ubuntu.com | signed chain; tested, not used in the case list |
| UPX 5.0.2 | GitHub release `upx-5.0.2-amd64_linux.tar.xz` | github.com/upx/upx | sha256 equals the GitHub asset digest `ddc26540...`; tested, not used (memfd stub, no malware counterpart) |
| musl | not downloaded: the dataset's own musl builds (amd64 musl 1.2.2 from jammy musl-dev; i386 musl 1.2.2 built from the jammy source) are reused as they are | workspace | dataset sha256 values |
| (Debian keyring, noble) | debian-archive-keyring 2023.4ubuntu1, for a bookworm UPX attempt | archive.ubuntu.com | signed chain; bookworm has no upx-ucl, so unused |

Not used: Bootlin. Its x86-64 releases start at 2021.11 (glibc 2.34) and it is built without the distribution
options (CET, `--enable-kernel`) whose effects are visible in the malware start-ups, while the distribution sysroots
above reproduce the malware start-ups call for call (section 4).

Sources were not downloaded again: `scripts/prepare_sources.py` unpacked the dataset's own .dsc files (SHA-256
re-checked against the earlier authentication records of the study; `dpkg-source -x` checked the tarballs; .dsc
signatures cannot be checked without uploader keys, authenticity comes from the signed jammy Sources index recorded
earlier): bzip2 1.0.8-5ubuntu0.1, gzip 1.10-4ubuntu4.2, coreutils 8.32-4.1ubuntu1.4, diffutils 3.8-0ubuntu2.1,
xz-utils 5.2.5-2ubuntu1.2, libzstd 1.4.8+dfsg-3build1, lz4 1.9.3-2build2, xxhash 0.8.1-1, ncompress 4.2.4.6-5,
brotli 1.0.9-2build6, expat 2.4.7-1ubuntu0.9, sqlite3 3.37.2-2ubuntu0.8, m4 1.4.18-5ubuntu2, cpio 2.13+dfsg-7ubuntu0.2.

## 2. What was built (395 new static binaries, all ET_EXEC, no PT_INTERP/PT_DYNAMIC)

| class | toolchain (bin dir) | x86-64 | i386 | programs |
|---|---|---|---|---|
| uclibc | GCC 4.1.2 + uClibc 0.9.30.1 | 9 | 9 | bzip2, compress, lz4, xxhsum, brotli, sqlite3, xmlwf, xz, zstd |
| glibc-static<2.35 | glibc 2.17 CentOS 7 | 27 | | 13 programs (bzip2, compress, lz4, xxhsum, brotli, sqlite3, xmlwf, gzip, cpio, m4, cmp, xz, zstd) + 14 coreutils (b2sum, base32, base64, basenc, cksum, md5sum, od, sha1sum, sha256sum, sha512sum, sort, sum, uniq, wc) |
| | glibc 2.27 Ubuntu 18.04 | 27 | | same 27 |
| | glibc 2.31 Ubuntu 20.04 | 27 | | same 27 |
| | glibc 2.12 CentOS 6 | | 27 | same 27 |
| | glibc 2.5 CentOS 5 | | 27 | same 27 |
| go | Go 1.13 / 1.16 (u-root v0.1.0 / v0.8.0) | 13 + 13 | 13 + 13 | u-root md5sum, shasum, gzip, sort, uniq, wc, hexdump, cmp, tar, cat; gojq; xxhsum (cespare); gxz (ulikunitz) |
| | Go 1.18 / 1.20 / 1.21 / 1.22 / 1.24 (u-root v0.10 / v0.11 / v0.12 / v0.14 / v0.16) | 5 x 14 | 5 x 14 | the same + u-root base64 |
| upx | UPX 3.94 over the uClibc builds | 9 | 9 | |
| | UPX 4.2.2 over glibc 2.31 (sort, xz, sqlite3, zstd, bzip2), uClibc bzip2, dataset glibc 2.35 (sha256sum, sort), dataset musl curl | 9 | | |
| | UPX 3.96 over glibc 2.31 (19 programs), dataset glibc 2.35 (2), dataset musl (2) | 23 | | not used in the list |
| total | | 227 | 168 | |

Plus 12 unchanged copies of dataset benign builds (glibc 2.35 and musl, both modes) in `bin/dataset-*`, used as UPX
inputs and reference start-ups. The committee's own static fingerprint rules (`../static_fingerprint.py`) put every
binary into its intended class (go 192, glibc-static 135+7, upx 50, uclibc 18, musl 5). Build flags: old glibc
`-O2 -fno-stack-protector -fcf-protection=none -fno-pie`, link `-static -no-pie` (CentOS 5 also `-fgnu89-inline`);
uClibc `-O2 -static`; Go default flags with `CGO_ENABLED=0`; UPX `-9`.

## 3. Host checks

Method (`scripts/host_check.py`, `scripts/check_cases.py`): each binary runs the dataset's task for that program
(`benign_workloads.py` arguments and fixtures; Go tools the same task kind with their own flags, e.g.
`shasum -a 256 <in>`, `tar -c -f o.tar <tree>`, `gxz -c <in>`), inputs in a private directory, stdin `/dev/null`,
20-s timeout, `LC_ALL=C`. Output verification: digests against Python's hashlib; base32/64 against Python;
compressor output decompressed (Python gzip/bz2/lzma, or the dataset's brotli/compress/lz4/zstd builds) and compared
with the input; sort/uniq/od/m4/sqlite3/cksum/sum/xxhsum stdout byte-equal to the dataset's glibc-2.35 build (host
coreutils 8.32 for sha1sum/sha512sum/uniq) run with the same arguments; cpio/tar: extracted/archived files equal the
fixture tree; jq: JSON-equal; xmlwf/cmp: exit 0 and no output; u-root hexdump against Go's hex.Dump format; u-root
wc: lines and bytes (it counts words differently on binary data). Exit codes recorded. Then the start-up: first 50
calls of the main process after `execve` under `strace -f`.

Results:
- light bin, all 395 new binaries: 385 pass, 10 fail = u-root `tar` v0.10.0-v0.16.0 (Go 1.18-1.24, both arches):
  `Rel: can't make <absolute dir> relative`, the dataset task needs an absolute fixture path; only the Go 1.13/1.16
  tar builds (u-root v0.1.0/v0.8.0) do the task. 8 further builds pass the light check but are not usable: u-root
  `base64` v0.10-v0.14 (Go 1.18-1.22) drops the last base64 quantum when the input length is not a multiple of 3
  (found on the medium input). The 12 dataset copies pass (network clients: `--version` smoke test only).
- every proposed case at its own bin: the 80 compute cases pass (heavy bins 0.03-1.2 s; slowest: uClibc bzip2
  medium 3.4-4.2 s, Go hexdump medium 6.6 s); the UPX-packed musl curl case is a Sink task (host: `--version` smoke,
  pass); 6 cases are unchanged dataset cases (guest-validated in revision5, not rerun).
- fixed during the work (all documented in the build logs/results): old-glibc `sqlite3` crashed with SIGSEGV on every
  run because a static glibc < 2.34 resolves `getpwuid()` (used by the shell to find `~/.sqliterc`) by
  `dlopen()`ing the system's libnss_files.so.2 (host 2.35, guest 2.43): linked with `-Wl,--wrap=getpwuid` and a
  3-line wrapper returning NULL (`scripts/shim/nopwent.c`; the shell then uses `$HOME`, same observable behaviour,
  no SQLite source changed). Other fixes: CentOS 5 headers need GNU89 inline semantics (`-fgnu89-inline`); xxhash on
  glibc < 2.16 needs `-Dstatic_assert=_Static_assert`; coreutils' `libstdbuf.so` cannot be linked `-static`
  (`--enable-no-install-program=stdbuf`); only `cmp` is built from diffutils (`diff` needs libpthread with GCC 11's
  libgcc_eh under static old glibc; the dataset uses `cmp`); the bzip2/lz4 Debian makefiles link a shared library
  (static `libbz2.a`/`liblz4.a` linked instead); zstd: `THREAD_LD=-lpthread` (the uClibc gcc wrapper ignores
  `-pthread`).

## 4. Start-up comparison with the malware of the same class (`checks/startup_compare.*`)

Malware start-ups are the VM recordings (kernel 7.0, `../startup_sequences.json`); benign ones are host strace
(kernel 6.8). These calls are issued by the C library/runtime, so the kernel difference should not matter, but a
guest run is the real confirmation. Five flags = (rseq, getrandom, set_robust_list, prlimit64, set_tid_address).

| class | benign build (proposed cases) | benign start-up | malware start-up | verdict |
|---|---|---|---|---|
| uClibc | GCC 4.1.2 + uClibc 0.9.30.1 | `ioctl ioctl` (stdio TCGETS on 0 and 1); threaded builds: `ioctl ioctl getpid getrlimit setrlimit rt_sigaction x3 rt_sigprocmask x2 brk brk` (linuxthreads) | all 10 x86-64 and 6 of 8 i386 uClibc malware begin `ioctl ioctl` (Gafgyt/Mirai/Tsunami/Katana/RapperBot); the threaded variant is identical to Mirai x86-64 and Gafgyt i386 | match; flags 00000 = malware 00000. 2 i386 Mirai start with `rt_sigprocmask` (no stdio before their own code): program-level, no benign counterpart |
| old glibc | CentOS 7 2.17 (sort, sqlite3, xz, zstd) | `uname brk brk arch_prctl set_tid_address set_robust_list rt_sigaction rt_sigaction rt_sigprocmask getrlimit` | Qilin x10: `brk brk arch_prctl set_tid_address set_robust_list rt_sigaction rt_sigaction rt_sigprocmask getrlimit` | same except the leading `uname` (Qilin's crosstool-NG glibc skips the kernel-version check); flags 00101 = Qilin |
| | Ubuntu 20.04 2.31 | `arch_prctl brk brk arch_prctl uname set_tid_address set_robust_list rt_sigaction rt_sigaction rt_sigprocmask prlimit64 readlink brk brk` | Akira x7: identical 14 calls | exact; flags 00111 |
| | Ubuntu 18.04 2.27 | `brk brk arch_prctl uname set_tid_address set_robust_list rt_sigaction rt_sigaction rt_sigprocmask prlimit64 readlink brk brk` | Kaiten (Ubuntu 18.04 GCC 7.5): identical 13 calls | exact; flags 00111. Akira x2 (`... prlimit64` without `uname`/`readlink`) has no exact counterpart; same flags |
| | CentOS 6 2.12 i386 | `uname brk brk set_thread_area set_tid_address set_robust_list futex futex rt_sigaction rt_sigaction rt_sigprocmask ugetrlimit uname brk brk` | ChinaZ/Dofloo x5 (Red Hat GCC 4.4.7): identical 15 calls | exact; flags 00101 |
| | CentOS 5 2.5 i386 | `uname brk brk set_thread_area set_tid_address set_robust_list futex rt_sigaction rt_sigaction rt_sigprocmask ugetrlimit uname brk brk` | XorDDoS x2 (Red Hat GCC 4.1.2): identical 14 calls (and the next two `rt_sigaction`) | exact; flags 00101. BillGates (Fedora Core 4, glibc 2.3.x: no `set_robust_list`, `_sysctl`) not reproduced |
| Go | 1.13-1.24 | amd64 `arch_prctl sched_getaffinity openat read close mmap ...`, 386 `set_thread_area sched_getaffinity open read close mmap2 ...` | all 15 + 6 Go malware: same; common prefix with the closest malware 7-40 calls (median per release) | match; flags 00000 |
| UPX | 3.94 over uClibc | amd64 `mmap readlink mmap mmap mprotect mmap mprotect mmap munmap ioctl ioctl`, i386 `mmap readlink mmap mprotect mmap mprotect mmap brk munmap ioctl ioctl` | Mirai/Tsunami UPX: identical for 3 of 3 x86-64 and 3 of 4 i386 (the 4th, Mirai, has one `mmap` less and no stdio) | exact |
| | 4.2.2 over glibc 2.31 / glibc 2.35 / musl | `open mmap mprotect readlink mmap mmap mprotect mmap mprotect mmap mprotect mmap mprotect mmap brk munmap` + inner start-up | Prometei x2 (inner = Ubuntu-20.04 glibc, threaded), GetShell (flags 11111), CoinMiner (flags 00001): identical stub | exact stub; inner flags 00111 / 11111 / 00001 = the three malware |
| musl, glibc>=2.35 | dataset builds | `arch_prctl/set_thread_area set_tid_address ...`; glibc 2.35 block | same | flags 00001 / 11111 |

Other measured facts: UPX 3.95/3.96 add one `mmap` (`open mmap mmap mprotect readlink`) and match no malware; UPX
3.91/3.94 cannot pack glibc programs (packer crash or SIGSEGV of the packed program); UPX 5.0.2 unpacks through
`memfd_create` (no malware counterpart). Old-glibc programs that do not link the pthread library have no nptl block
(`uname brk brk arch_prctl readlink brk brk ...`, flags 00000), a vector no old-glibc malware shows (all 20 x86-64
and 7 of 8 i386 malware have `set_robust_list`, the 8th has `set_tid_address`), so the old-glibc slots use only
the pthread-linked programs sort, sqlite3, xz and zstd. All other old-glibc builds (23 per toolchain) are built and checked but not proposed.

Residual static (not system-call) difference: the old-glibc builds carry two `.comment` strings, the distribution
compiler from libc.a's objects (e.g. `GCC: (GNU) 4.4.7 20120313 (Red Hat 4.4.7-23)`, like ChinaZ/Dofloo) and
`GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.3) 11.4.0` from the host compiler.

## 5. Proposed case list (not collected)

Counts (x86-64 59, i386 28), against the static malware mix:

| mode | class | benign cases | malware | sub-split of the benign cases |
|---|---|---|---|---|
| x86-64 | glibc-static<2.35 | 21 | 20 | CentOS 7 2.17: 11 (Qilin x10), Ubuntu 20.04 2.31: 7 (Akira x7), Ubuntu 18.04 2.27: 3 (Kaiten + Akira x2) |
| | go | 16 | 15 | 1.13: 2, 1.16: 2, 1.18: 4, 1.20: 2, 1.21: 1, 1.24: 5 |
| | uclibc | 11 | 10 | 10 without threads + 1 linuxthreads (malware 9 + 1) |
| | upx | 7 | 7 | 3.94 over uClibc: 3 (1 linuxthreads, like Mirai); 4.2.2 over glibc 2.31: 2 (Prometei), glibc 2.35: 1 (GetShell), musl: 1 (CoinMiner) |
| | musl | 2 | 2 | dataset cases (wget, openssl; Sink tasks) |
| | glibc-static>=2.35 | 2 | 2 | dataset cases (b2sum, md5sum) |
| | (no start-up recorded) | 0 | 1 | NoEscape crashed |
| i386 | glibc-static<2.35 | 8 | 8 | CentOS 6 2.12: 5 (ChinaZ/Dofloo x5), CentOS 5 2.5: 3 (XorDDoS x2, BillGates) |
| | uclibc | 8 | 8 | 7 without threads + 1 linuxthreads (malware 7 + 1) |
| | go | 6 | 6 | 1.20: 5, 1.22: 1 |
| | upx | 4 | 4 | 3.94 over uClibc |
| | musl | 2 | 2 | dataset cases (curl, wget; Sink tasks) |

x86-64 counts are the malware's 56 classified start-ups scaled to 59 by largest remainder; i386 is 1:1. Tasks are the
dataset's tasks; bins rotate light/medium/heavy per program. Splits keep whole projects together: projects already in
the dataset keep the dataset's benign split, the new Go projects are u-root/cespare-xxhash = train, gojq/ulikunitz-xz
= test. Resulting train/test per class: x86-64 old glibc 6/15, go 12/4, uclibc 8/3, upx 5/2, musl 1/1, glibc 2.35
2/0 (34/25); i386 old glibc 3/5, go 4/2, uclibc 5/3, upx 3/1, musl 1/1 (16/12) (the malware are family-held-out: x86-64 old glibc
20/0, i386 old glibc 0/8), so a re-assignment may be wanted.

| case | mode | class | toolchain | project | program | task argv | bin | exit | host check | sha256 (16) |
|---|---|---|---|---|---|---|---|---|---|---|
| tcm-x64-000 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | coreutils | sort | `<in>` | light | 0 | pass | `319483612ff2fc57` |
| tcm-x64-001 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | coreutils | sort | `<in>` | medium | 0 | pass | `319483612ff2fc57` |
| tcm-x64-002 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | coreutils | sort | `<in>` | heavy | 0 | pass | `319483612ff2fc57` |
| tcm-x64-003 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | sqlite3 | sqlite3 | `t.db '.read <s>'` | light | 0 | pass | `8ba7f6c10223949c` |
| tcm-x64-004 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | sqlite3 | sqlite3 | `t.db '.read <s>'` | medium | 0 | pass | `8ba7f6c10223949c` |
| tcm-x64-005 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | sqlite3 | sqlite3 | `t.db '.read <s>'` | heavy | 0 | pass | `8ba7f6c10223949c` |
| tcm-x64-006 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | xz-utils | xz | `-c -T1 <in>` | light | 0 | pass | `98b5cfc4a87a3c44` |
| tcm-x64-007 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | xz-utils | xz | `-c -T1 <in>` | medium | 0 | pass | `98b5cfc4a87a3c44` |
| tcm-x64-008 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | xz-utils | xz | `-c -T1 <in>` | heavy | 0 | pass | `98b5cfc4a87a3c44` |
| tcm-x64-009 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | libzstd | zstd | `-q <in> -o o.zst` | light | 0 | pass | `49a206114c201bf5` |
| tcm-x64-010 | amd64 | glibc-static<2.35 | glibc2.17-centos7-x86_64 | libzstd | zstd | `-q <in> -o o.zst` | medium | 0 | pass | `49a206114c201bf5` |
| tcm-x64-011 | amd64 | glibc-static<2.35 | glibc2.31-focal-x86_64 | coreutils | sort | `<in>` | medium | 0 | pass | `bb7a3319f5e20a9c` |
| tcm-x64-012 | amd64 | glibc-static<2.35 | glibc2.31-focal-x86_64 | coreutils | sort | `<in>` | heavy | 0 | pass | `bb7a3319f5e20a9c` |
| tcm-x64-013 | amd64 | glibc-static<2.35 | glibc2.31-focal-x86_64 | sqlite3 | sqlite3 | `t.db '.read <s>'` | medium | 0 | pass | `d782d854810d6682` |
| tcm-x64-014 | amd64 | glibc-static<2.35 | glibc2.31-focal-x86_64 | sqlite3 | sqlite3 | `t.db '.read <s>'` | heavy | 0 | pass | `d782d854810d6682` |
| tcm-x64-015 | amd64 | glibc-static<2.35 | glibc2.31-focal-x86_64 | xz-utils | xz | `-c -T1 <in>` | light | 0 | pass | `6538c13d44d7f6c2` |
| tcm-x64-016 | amd64 | glibc-static<2.35 | glibc2.31-focal-x86_64 | xz-utils | xz | `-c -T1 <in>` | heavy | 0 | pass | `6538c13d44d7f6c2` |
| tcm-x64-017 | amd64 | glibc-static<2.35 | glibc2.31-focal-x86_64 | libzstd | zstd | `-q <in> -o o.zst` | medium | 0 | pass | `abd4f10f8f65a682` |
| tcm-x64-018 | amd64 | glibc-static<2.35 | glibc2.27-bionic-x86_64 | coreutils | sort | `<in>` | light | 0 | pass | `89237a2a68f240d1` |
| tcm-x64-019 | amd64 | glibc-static<2.35 | glibc2.27-bionic-x86_64 | sqlite3 | sqlite3 | `t.db '.read <s>'` | heavy | 0 | pass | `216bd1e60dcb68b9` |
| tcm-x64-020 | amd64 | glibc-static<2.35 | glibc2.27-bionic-x86_64 | libzstd | zstd | `-q <in> -o o.zst` | heavy | 0 | pass | `f33616523622a656` |
| tcm-x64-021 | amd64 | go | go1.13.15-amd64 | github.com/itchyny/gojq | gojq | `-c . <in>` | light | 0 | pass | `f77115604d57dfcf` |
| tcm-x64-022 | amd64 | go | go1.13.15-amd64 | github.com/u-root/u-root | tar | `-c -f o.tar <tree>` | medium | 0 | pass | `999963e2cff19853` |
| tcm-x64-023 | amd64 | go | go1.16.15-amd64 | github.com/ulikunitz/xz | gxz | `-c <in>` | medium | 0 | pass | `43565916f31343b6` |
| tcm-x64-024 | amd64 | go | go1.16.15-amd64 | github.com/u-root/u-root | sort | `<in>` | light | 0 | pass | `b2d8e78f6249aa41` |
| tcm-x64-025 | amd64 | go | go1.18.10-amd64 | github.com/u-root/u-root | md5sum | `<in>` | light | 0 | pass | `d20d3b7ccd6b500a` |
| tcm-x64-026 | amd64 | go | go1.18.10-amd64 | github.com/cespare/xxhash/v2 | xxhsum-go | `<in>` | medium | 0 | pass | `6c29e7ec805d04e5` |
| tcm-x64-027 | amd64 | go | go1.18.10-amd64 | github.com/u-root/u-root | gzip | `-c <in>` | heavy | 0 | pass | `32cb19d193aff045` |
| tcm-x64-028 | amd64 | go | go1.18.10-amd64 | github.com/u-root/u-root | cmp | `<a> <b>` | light | 0 | pass | `5b2ecd137dd049db` |
| tcm-x64-029 | amd64 | go | go1.20.14-amd64 | github.com/u-root/u-root | hexdump | `<in>` | medium | 0 | pass | `fd550287cfee06b5` |
| tcm-x64-030 | amd64 | go | go1.20.14-amd64 | github.com/u-root/u-root | uniq | `<in>` | light | 0 | pass | `cced09a4a98e62ba` |
| tcm-x64-031 | amd64 | go | go1.21.13-amd64 | github.com/u-root/u-root | shasum | `-a 256 <in>` | heavy | 0 | pass | `4222504ef38f0724` |
| tcm-x64-032 | amd64 | go | go1.24.13-amd64 | github.com/itchyny/gojq | gojq | `-c . <in>` | medium | 0 | pass | `a2fb2bd425668017` |
| tcm-x64-033 | amd64 | go | go1.24.13-amd64 | github.com/ulikunitz/xz | gxz | `-c <in>` | light | 0 | pass | `81ac2e76fe7270c8` |
| tcm-x64-034 | amd64 | go | go1.24.13-amd64 | github.com/u-root/u-root | wc | `<in>` | medium | 0 | pass | `c68fb8e7133e5bc5` |
| tcm-x64-035 | amd64 | go | go1.24.13-amd64 | github.com/u-root/u-root | hexdump | `<in>` | light | 0 | pass | `7c47523ced21bdb1` |
| tcm-x64-036 | amd64 | go | go1.24.13-amd64 | github.com/u-root/u-root | cat | `<in>` | heavy | 0 | pass | `c3ff705d175f95d3` |
| tcm-x64-037 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | bzip2 | bzip2 | `-c <in>` | light | 0 | pass | `61615422e54c4aa2` |
| tcm-x64-038 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | bzip2 | bzip2 | `-c <in>` | medium | 0 | pass | `61615422e54c4aa2` |
| tcm-x64-039 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | ncompress | compress | `-c <in>` | light | 0 | pass | `d00ffbbb2b77b7fc` |
| tcm-x64-040 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | ncompress | compress | `-c <in>` | heavy | 0 | pass | `d00ffbbb2b77b7fc` |
| tcm-x64-041 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | lz4 | lz4 | `-qf <in> o.lz4` | medium | 0 | pass | `641268e8b70dd572` |
| tcm-x64-042 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | lz4 | lz4 | `-qf <in> o.lz4` | heavy | 0 | pass | `641268e8b70dd572` |
| tcm-x64-043 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | xxhash | xxhsum | `<in>` | light | 0 | pass | `932fcf36b8004c0f` |
| tcm-x64-044 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | xxhash | xxhsum | `<in>` | medium | 0 | pass | `932fcf36b8004c0f` |
| tcm-x64-045 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | brotli | brotli | `-c <in>` | light | 0 | pass | `511c96392915c5f3` |
| tcm-x64-046 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | expat | xmlwf | `<in>` | medium | 0 | pass | `3b2591f1f574c650` |
| tcm-x64-047 | amd64 | uclibc | uclibc0.9.30.1-gcc4.1.2-x86_64 | libzstd | zstd | `-q <in> -o o.zst` | light | 0 | pass | `e01d760865fd4a89` |
| tcm-x64-048 | amd64 | upx | upx3.94-uclibc0.9.30.1-gcc4.1.2-x86_64 | bzip2 | bzip2 | `-c <in>` | medium | 0 | pass | `4978dd681acd343b` |
| tcm-x64-049 | amd64 | upx | upx3.94-uclibc0.9.30.1-gcc4.1.2-x86_64 | lz4 | lz4 | `-qf <in> o.lz4` | light | 0 | pass | `2045190d2c994c2d` |
| tcm-x64-050 | amd64 | upx | upx3.94-uclibc0.9.30.1-gcc4.1.2-x86_64 | libzstd | zstd | `-q <in> -o o.zst` | heavy | 0 | pass | `c569f5cded4569df` |
| tcm-x64-051 | amd64 | upx | upx4.2.2-glibc2.31-focal-x86_64 | coreutils | sort | `<in>` | light | 0 | pass | `eb9b298ae6d7ef1f` |
| tcm-x64-052 | amd64 | upx | upx4.2.2-glibc2.31-focal-x86_64 | xz-utils | xz | `-c -T1 <in>` | medium | 0 | pass | `fc22ef69343a3ef6` |
| tcm-x64-053 | amd64 | upx | upx4.2.2-dataset-glibc2.35-x86_64 | coreutils | sha256sum | `<in>` | medium | 0 | pass | `ca9f38dfa8bad3b8` |
| tcm-x64-054 | amd64 | upx | upx4.2.2-dataset-musl-x86_64 | curl | curl | `--version` | - | 0 | pass (smoke) | `716c4ac3756d6ba2` |
| tcm-x64-055 | amd64 | glibc-static>=2.35 | dataset (unchanged) | coreutils | b2sum | `stream (dataset task, variant light)` | light | 0 | dataset case | `e15680a29c8d07d5` |
| tcm-x64-056 | amd64 | glibc-static>=2.35 | dataset (unchanged) | coreutils | md5sum | `stream (dataset task, variant light)` | light | 0 | dataset case | `86b0951fdf7087c7` |
| tcm-x64-057 | amd64 | musl | dataset (unchanged) | wget | wget | `net (dataset task, variant a)` | net | Sink | dataset case | `0a23aee03f7be56b` |
| tcm-x64-058 | amd64 | musl | dataset (unchanged) | openssl | openssl | `net (dataset task, variant a)` | net | Sink | dataset case | `21ba90cb61be1a97` |
| tcm-i386-059 | i386 | glibc-static<2.35 | glibc2.12-centos6-i686 | coreutils | sort | `<in>` | light | 0 | pass | `cdf8a2bdd6465758` |
| tcm-i386-060 | i386 | glibc-static<2.35 | glibc2.12-centos6-i686 | coreutils | sort | `<in>` | medium | 0 | pass | `cdf8a2bdd6465758` |
| tcm-i386-061 | i386 | glibc-static<2.35 | glibc2.12-centos6-i686 | sqlite3 | sqlite3 | `t.db '.read <s>'` | light | 0 | pass | `2e60ce3f37893337` |
| tcm-i386-062 | i386 | glibc-static<2.35 | glibc2.12-centos6-i686 | xz-utils | xz | `-c -T1 <in>` | medium | 0 | pass | `b0a52f95fae296e1` |
| tcm-i386-063 | i386 | glibc-static<2.35 | glibc2.12-centos6-i686 | libzstd | zstd | `-q <in> -o o.zst` | heavy | 0 | pass | `4896c8c311ef9557` |
| tcm-i386-064 | i386 | glibc-static<2.35 | glibc2.5-centos5-i386 | coreutils | sort | `<in>` | heavy | 0 | pass | `326840dab68a45cc` |
| tcm-i386-065 | i386 | glibc-static<2.35 | glibc2.5-centos5-i386 | sqlite3 | sqlite3 | `t.db '.read <s>'` | medium | 0 | pass | `757decaf58a22dce` |
| tcm-i386-066 | i386 | glibc-static<2.35 | glibc2.5-centos5-i386 | xz-utils | xz | `-c -T1 <in>` | light | 0 | pass | `8c6974bd968cbc5c` |
| tcm-i386-067 | i386 | uclibc | uclibc0.9.30.1-gcc4.1.2-i686 | bzip2 | bzip2 | `-c <in>` | light | 0 | pass | `1925f7f991806abb` |
| tcm-i386-068 | i386 | uclibc | uclibc0.9.30.1-gcc4.1.2-i686 | bzip2 | bzip2 | `-c <in>` | medium | 0 | pass | `1925f7f991806abb` |
| tcm-i386-069 | i386 | uclibc | uclibc0.9.30.1-gcc4.1.2-i686 | ncompress | compress | `-c <in>` | medium | 0 | pass | `c4c834483fe75bb6` |
| tcm-i386-070 | i386 | uclibc | uclibc0.9.30.1-gcc4.1.2-i686 | lz4 | lz4 | `-qf <in> o.lz4` | heavy | 0 | pass | `1ff6e50561ed83cb` |
| tcm-i386-071 | i386 | uclibc | uclibc0.9.30.1-gcc4.1.2-i686 | xxhash | xxhsum | `<in>` | light | 0 | pass | `61eb6ef63a6a8574` |
| tcm-i386-072 | i386 | uclibc | uclibc0.9.30.1-gcc4.1.2-i686 | brotli | brotli | `-c <in>` | medium | 0 | pass | `ac6698658e61cb10` |
| tcm-i386-073 | i386 | uclibc | uclibc0.9.30.1-gcc4.1.2-i686 | expat | xmlwf | `<in>` | light | 0 | pass | `55ae14655c1a518d` |
| tcm-i386-074 | i386 | uclibc | uclibc0.9.30.1-gcc4.1.2-i686 | libzstd | zstd | `-q <in> -o o.zst` | medium | 0 | pass | `8c82998f3859dc96` |
| tcm-i386-075 | i386 | go | go1.20.14-386 | github.com/itchyny/gojq | gojq | `-c . <in>` | light | 0 | pass | `6c7f1ff9242e009e` |
| tcm-i386-076 | i386 | go | go1.20.14-386 | github.com/u-root/u-root | md5sum | `<in>` | medium | 0 | pass | `5fc4baeccfbf15e0` |
| tcm-i386-077 | i386 | go | go1.20.14-386 | github.com/ulikunitz/xz | gxz | `-c <in>` | light | 0 | pass | `387b1d653aaa8d6c` |
| tcm-i386-078 | i386 | go | go1.20.14-386 | github.com/u-root/u-root | sort | `<in>` | medium | 0 | pass | `3b40836b3c6230cb` |
| tcm-i386-079 | i386 | go | go1.20.14-386 | github.com/cespare/xxhash/v2 | xxhsum-go | `<in>` | heavy | 0 | pass | `a0129938124753a4` |
| tcm-i386-080 | i386 | go | go1.22.12-386 | github.com/u-root/u-root | cmp | `<a> <b>` | light | 0 | pass | `34be7d8fca3e492d` |
| tcm-i386-081 | i386 | upx | upx3.94-uclibc0.9.30.1-gcc4.1.2-i686 | ncompress | compress | `-c <in>` | light | 0 | pass | `4f81db1112100af9` |
| tcm-i386-082 | i386 | upx | upx3.94-uclibc0.9.30.1-gcc4.1.2-i686 | lz4 | lz4 | `-qf <in> o.lz4` | medium | 0 | pass | `76363e12b22e1e48` |
| tcm-i386-083 | i386 | upx | upx3.94-uclibc0.9.30.1-gcc4.1.2-i686 | xxhash | xxhsum | `<in>` | medium | 0 | pass | `0a6a7877029cabf8` |
| tcm-i386-084 | i386 | upx | upx3.94-uclibc0.9.30.1-gcc4.1.2-i686 | expat | xmlwf | `<in>` | heavy | 0 | pass | `3f839f36113aea39` |
| tcm-i386-085 | i386 | musl | dataset (unchanged) | curl | curl | `net (dataset task, variant a)` | net | Sink | dataset case | `ab7a2b716bea34fa` |
| tcm-i386-086 | i386 | musl | dataset (unchanged) | wget | wget | `net (dataset task, variant a)` | net | Sink | dataset case | `72b6617b3e4f2a03` |

`<in>`, `<a>`, `<b>`, `<tree>`, `<s>` = absolute staged fixture paths (roles of `benign_workloads.py`); outputs are
relative to the run directory. "Sink" = network case, accepted when it reaches the Sink (dataset rule). Full records
(fixtures and sizes, full SHA-256, inner binary of UPX cases, start-up prefix, flags, best malware match, host-check
argv/time) are in `proposed_cases.json` and `manifest.json`.

## 6. Limitations and things that were not done

- Guest confirmation is outstanding: all start-ups above are host strace; a VM collection needs approval.
- Old glibc: the compiler is host GCC 11.4 with the distribution's static glibc (the start-up comes from libc.a);
  Qilin's exact start-up (no leading `uname`), Akira's two `prlimit64`-without-`uname/readlink` samples and BillGates'
  glibc 2.3 start-up have no exact counterpart. Any old-glibc static program that calls `getpw*`/`getgr*` would crash
  in the guest like sqlite3 did (none of the proposed sort/xz/zstd do; sqlite3 is wrapped).
- Few projects behind some classes: old glibc uses 4 projects (coreutils sort, sqlite3, xz-utils, libzstd) and the
  same program appears from several old-glibc toolchains (near-identical behaviour apart from start-up); Go is
  dominated by u-root (11 of 16 x86-64 Go cases). Keep whole projects in one split.
- Only 5 of the 87 proposed cases are network tasks (the dataset benign had 27/105); the rebuilt programs are compute
  programs. The remaining dataset network benign could be kept alongside.
- uClibc 0.9.30.1 (this build: no `program_invocation_name`) cannot build the gnulib projects: gzip, cpio, m4,
  diffutils and coreutils stop at gnulib's `getprogname` ("not ported to this OS"); not patched.
- Go tools are other implementations of the same task kinds (not the dataset's C programs); u-root `wc` counts words
  differently on binary input; `hexdump` replaces `od`.
- Heavy bins of uClibc/UPX bzip2 took 14-17 s on this host, so those cases use the medium bin to stay clear of the
  20-s observation.
- Disk: about 11 GB here; `builds/*/<project>/` trees (3.5 GB) and `gopath/cache` can be deleted, the binaries,
  results and logs are what the manifest refers to.

## 7. Reproduce (from this folder, host only)

```
/usr/bin/python3 -I scripts/fetch_go.py $PWD
/usr/bin/python3 -I scripts/fetch_uclibc_cross.py $PWD
/usr/bin/python3 -I scripts/fetch_ubuntu.py $PWD ubuntu-{bionic,focal,xenial}-amd64 archive {suite} amd64 libc6-dev linux-libc-dev
/usr/bin/python3 -I scripts/fetch_centos.py $PWD centos7-x86_64 7 7.9.2009/os/x86_64/Packages glibc-{devel,static,headers}-2.17-317.el7.x86_64.rpm kernel-headers-3.10.0-1160.el7.x86_64.rpm
/usr/bin/python3 -I scripts/fetch_centos.py $PWD centos6-i686 6 6.10/os/i386/Packages glibc-{devel,static,headers}-2.12-1.212.el6.i686.rpm kernel-headers-2.6.32-754.el6.i686.rpm
/usr/bin/python3 -I scripts/fetch_centos.py $PWD centos5-i386 5 5.11/os/i386/CentOS glibc-{devel,headers}-2.5-123.i386.rpm kernel-headers-2.6.18-398.el5.i386.rpm
/usr/bin/python3 -I scripts/fetch_ubuntu.py $PWD upx-ucl-bionic archive bionic amd64 upx-ucl libucl1   # likewise noble (+libc6 libgcc-s1 libstdc++6 zlib1g), jammy, focal, xenial
/usr/bin/python3 -I scripts/prepare_sources.py $PWD          # + sqlite3 amalgamation: configure && make sqlite3.c shell.c (logs/sqlite3-amalg-*)
J=8 /usr/bin/python3 -I scripts/build_c.py $PWD <toolchain> bzip2 ncompress lz4 xxhash brotli sqlite3 expat gzip cpio m4 diffutils xz-utils libzstd coreutils
scripts/run_go_builds.sh $PWD
/usr/bin/python3 -I scripts/pack_upx.py $PWD upx3.94 uclibc0.9.30.1-gcc4.1.2-x86_64      # etc., see builds/upx-results.json
/usr/bin/python3 -I scripts/host_check.py $PWD --bins light
/usr/bin/python3 -I scripts/startup_compare.py $PWD checks/host_check-light.json
/usr/bin/python3 -I scripts/propose_cases.py $PWD && /usr/bin/python3 -I scripts/check_cases.py $PWD
/usr/bin/python3 -I scripts/make_manifest.py $PWD
```
