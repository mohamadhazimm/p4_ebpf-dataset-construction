"""Build the dataset's benign C programs (static) with one toolchain profile and record every output.

    /usr/bin/python3 -I scripts/build_c.py <benign-build dir> <toolchain> <project> [<project> ...]

Each build runs in a fresh copy of benign-build/sources/<project> under builds/<toolchain>/<project>; the log goes to
logs/build-<toolchain>-<project>.log; every produced program is checked from its ELF header (ET_EXEC, no PT_INTERP,
no PT_DYNAMIC, expected machine) and copied to bin/<toolchain>/<program>. Results append to
builds/<toolchain>/results.json. Benign sources only; nothing is executed except the projects' own build steps.
"""
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

BB = Path(sys.argv[1]).resolve()
TC = BB / "toolchains"
U64 = TC / "uclibc-0.9.30.1-x86_64/cross-compiler-x86_64/bin"
U32 = TC / "uclibc-0.9.30.1-i686/cross-compiler-i686/bin"
G32 = TC / "lib32gcc-11"
HARDEN_OFF = "-fno-stack-protector -fcf-protection=none -fno-pie"


def glibc_profile(tag, libdir, m32):
    s = TC / tag / "sysroot"
    lib = s / libdir
    cc = "gcc %s--sysroot=%s -B%s/ -L%s" % ("-m32 " if m32 else "", s, lib, lib)
    if m32:
        cc += " -B%s/ -L%s" % (G32, G32)
    return {"CC": cc, "AR": "ar", "RANLIB": "ranlib", "CFLAGS": "-O2 " + HARDEN_OFF, "LDFLAGS": "-static -no-pie",
            "host": "i686-linux-gnu" if m32 else "", "machine": 3 if m32 else 62,
            "mode": "i386_static" if m32 else "amd64_static", "extra_env": {"TIME_T_32_BIT_OK": "yes"} if m32 else {}}


PROFILES = {
    "uclibc0.9.30.1-gcc4.1.2-x86_64": {"CC": str(U64 / "x86_64-gcc"), "AR": str(U64 / "x86_64-ar"),
                                        "RANLIB": str(U64 / "x86_64-ranlib"), "CFLAGS": "-O2", "LDFLAGS": "-static",
                                        "host": "x86_64-unknown-linux", "machine": 62, "mode": "amd64_static",
                                        "extra_env": {}},
    "uclibc0.9.30.1-gcc4.1.2-i686": {"CC": str(U32 / "i686-gcc"), "AR": str(U32 / "i686-ar"),
                                      "RANLIB": str(U32 / "i686-ranlib"), "CFLAGS": "-O2", "LDFLAGS": "-static",
                                      "host": "i686-unknown-linux", "machine": 3, "mode": "i386_static",
                                      "extra_env": {"TIME_T_32_BIT_OK": "yes"}},
    "glibc2.17-centos7-x86_64": glibc_profile("centos7-x86_64", "usr/lib64", False),
    "glibc2.23-xenial-x86_64": glibc_profile("ubuntu-xenial-amd64", "usr/lib/x86_64-linux-gnu", False),
    "glibc2.27-bionic-x86_64": glibc_profile("ubuntu-bionic-amd64", "usr/lib/x86_64-linux-gnu", False),
    "glibc2.31-focal-x86_64": glibc_profile("ubuntu-focal-amd64", "usr/lib/x86_64-linux-gnu", False),
    "glibc2.12-centos6-i686": glibc_profile("centos6-i686", "usr/lib", True),
    "glibc2.5-centos5-i386": glibc_profile("centos5-i386", "usr/lib", True),
}

# glibc 2.5 headers predate GCC's C99 inline semantics: keep GNU89 inline so `extern __inline` stays inline-only
PROFILES["glibc2.5-centos5-i386"]["CFLAGS"] += " -fgnu89-inline"

# recipe: (shell script run in the build tree, {program: relative path})
AUTO = 'CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS" ./configure $HOSTARG ' \
       '--disable-dependency-tracking --disable-nls'
RECIPES = {
    "bzip2": ('make -j$J CC="$CC" AR="$AR" RANLIB="$RANLIB" CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64" '
              'libbz2.a bzip2.o && $CC $CFLAGS $LDFLAGS -o bzip2 bzip2.o libbz2.a', {"bzip2": "bzip2"}),
    "ncompress": ('$CC $CFLAGS -DDIRENT=1 -DUSERMEM=800000 -DREGISTERS=3 -DLSTAT=1 -DUTIME_H=1 -o compress '
                  'compress42.c $LDFLAGS', {"compress": "compress"}),
    "lz4": ('make -j$J -C lib liblz4.a CC="$CC" AR="$AR" CFLAGS="$CFLAGS" DEBUGFLAGS= && '
            'make -j$J -C programs lz4 CC="$CC" AR="$AR" CFLAGS="$CFLAGS" DEBUGFLAGS= LDFLAGS="$LDFLAGS"',
            {"lz4": "programs/lz4"}),
    "xxhash": ('make -j$J xxhsum CC="$CC" AR="$AR" CFLAGS="$CFLAGS -Dstatic_assert=_Static_assert" DEBUGFLAGS= '
               'LDFLAGS="$LDFLAGS"',
               {"xxhsum": "xxhsum"}),
    "brotli": ('$CC $CFLAGS -std=gnu99 -Ic/include c/common/*.c c/dec/*.c c/enc/*.c c/tools/brotli.c -o brotli '
               '$LDFLAGS -lm', {"brotli": "brotli"}),
    "sqlite3": ('$CC $CFLAGS -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION=1 -DHAVE_USLEEP=1 '
                '-I$AMALG $AMALG/shell.c $AMALG/sqlite3.c $SQLITE_EXTRA -o sqlite3 $LDFLAGS -lpthread -lm',
                {"sqlite3": "sqlite3"}),
    "gzip": (AUTO + ' && make -j$J MAKEINFO=true', {"gzip": "gzip"}),
    "cpio": (AUTO + ' && make -j$J MAKEINFO=true', {"cpio": "src/cpio"}),
    "m4": (AUTO + ' --without-libsigsegv && make -j$J MAKEINFO=true', {"m4": "src/m4"}),
    "diffutils": (AUTO + ' && make -j$J -C lib && make -C src version.h && make -j$J -C src cmp', {"cmp": "src/cmp"}),
    "coreutils": (AUTO + ' --without-gmp --without-libcap --without-libacl --without-selinux --without-openssl '
                  '--disable-libsmack --enable-no-install-program=stdbuf && make -j$J MAKEINFO=true',
                  {p: "src/" + p for p in ("b2sum", "base32", "base64", "basenc", "cksum", "md5sum", "od", "sha1sum",
                                           "sha256sum", "sha512sum", "sort", "sum", "uniq", "wc")}),
    "expat": ('cd expat && ./buildconf.sh && ' + AUTO + ' --disable-shared --enable-static --without-docbook --without-examples '
              '--without-tests && make -j$J -C lib && make -j$J -C xmlwf LDFLAGS="$LDFLAGS -all-static"',
              {"xmlwf": "expat/xmlwf/xmlwf"}),
    "xz-utils": (AUTO + ' --disable-shared --enable-static --disable-doc --disable-lzmadec --disable-lzmainfo '
                 '--disable-scripts --disable-xzdec && make -j$J -C src/liblzma && '
                 'make -j$J -C src/xz LDFLAGS="$LDFLAGS -all-static"', {"xz": "src/xz/xz"}),
    "libzstd": ('make -j$J -C programs zstd CC="$CC" AR="$AR" THREAD_LD=-lpthread DEBUGFLAGS= '
                'HAVE_ZLIB=0 HAVE_LZMA=0 HAVE_LZ4=0', {"zstd": "programs/zstd"}),  # CFLAGS/LDFLAGS from env
}
AUTORECONF = {"gzip"}  # as in the dataset's own builds


def elf_facts(path):
    b = path.read_bytes()
    if b[:4] != b"\x7fELF":
        return {"elf": False}
    cls = b[4]
    if cls == 2:
        e_type, e_machine = struct.unpack_from("<HH", b, 16)
        phoff, = struct.unpack_from("<Q", b, 32)
        phentsize, phnum = struct.unpack_from("<HH", b, 54)
    else:
        e_type, e_machine = struct.unpack_from("<HH", b, 16)
        phoff, = struct.unpack_from("<I", b, 28)
        phentsize, phnum = struct.unpack_from("<HH", b, 42)
    types = [struct.unpack_from("<I", b, phoff + i * phentsize)[0] for i in range(phnum)]
    comment = None
    try:
        out = subprocess.run(["readelf", "-p", ".comment", str(path)], capture_output=True, text=True).stdout
        comment = sorted(set(l.split("]", 1)[1].strip() for l in out.splitlines() if "]" in l))
    except Exception:
        pass
    return {"elf": True, "class": 64 if cls == 2 else 32, "e_type": e_type, "e_machine": e_machine,
            "pt_interp": 3 in types, "pt_dynamic": 2 in types, "size": len(b),
            "sha256": hashlib.sha256(b).hexdigest(), "comment": comment}


def main():
    tool = sys.argv[2]
    projects = sys.argv[3:]
    prof = PROFILES[tool]
    jobs = os.environ.get("J", "8")
    resfile = BB / "builds" / tool / "results.json"
    resfile.parent.mkdir(parents=True, exist_ok=True)
    results = json.loads(resfile.read_text()) if resfile.exists() else {}
    for project in projects:
        script, programs = RECIPES[project]
        tree = BB / "builds" / tool / project
        if tree.exists():
            shutil.rmtree(tree)
        shutil.copytree(BB / "sources" / project, tree, symlinks=True)
        log = BB / "logs" / ("build-%s-%s.log" % (tool, project))
        env = dict(os.environ, CC=prof["CC"], AR=prof["AR"], RANLIB=prof["RANLIB"], CFLAGS=prof["CFLAGS"],
                   LDFLAGS=prof["LDFLAGS"], J=jobs, LC_ALL="C", HOME=str(tree),
                   HOSTARG=("--host=" + prof["host"]) if prof["host"] else "",
                   AMALG=str(BB / "sources/sqlite3-amalgamation"),
                   SQLITE_EXTRA=("%s -Wl,--wrap=getpwuid" % (BB / "scripts/shim/nopwent.c"))
                   if tool.startswith("glibc") else "",
                   **prof["extra_env"])
        full = ("autoreconf -fi && " if project in AUTORECONF else "") + script
        t0 = time.time()
        with open(log, "w") as lf:
            lf.write("toolchain=%s project=%s\nCC=%s\nCFLAGS=%s\nLDFLAGS=%s\nscript=%s\n\n" % (
                tool, project, prof["CC"], prof["CFLAGS"], prof["LDFLAGS"], full))
            lf.flush()
            r = subprocess.run(["bash", "-c", "set -e; " + full], cwd=tree, env=env, stdout=lf, stderr=subprocess.STDOUT)
        rec = {"project": project, "toolchain": tool, "mode": prof["mode"], "returncode": r.returncode,
               "seconds": round(time.time() - t0, 1), "log": str(log.relative_to(BB)), "script": full,
               "CC": prof["CC"], "CFLAGS": prof["CFLAGS"], "LDFLAGS": prof["LDFLAGS"], "programs": {}}
        bindir = BB / "bin" / tool
        bindir.mkdir(parents=True, exist_ok=True)
        for prog, rel in programs.items():
            p = tree / rel
            if not p.exists() or p.is_symlink():
                rec["programs"][prog] = {"status": "missing"}
                continue
            f = elf_facts(p)
            ok = (f.get("elf") and f["e_type"] == 2 and not f["pt_interp"] and not f["pt_dynamic"]
                  and f["e_machine"] == prof["machine"])
            if ok:
                shutil.copy2(p, bindir / prog)
            rec["programs"][prog] = {"status": "ok" if ok else "bad_elf", **f,
                                     "bin": str((bindir / prog).relative_to(BB)) if ok else None}
        results[project] = rec
        resfile.write_text(json.dumps(results, indent=1))
        print("%-32s %-10s rc=%d %5.0fs %s" % (tool, project, r.returncode, rec["seconds"],
                                               {k: v["status"] for k, v in rec["programs"].items()}), flush=True)


if __name__ == "__main__":
    main()
