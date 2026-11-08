#!/usr/bin/env bash
# Build static amd64 (musl) network clients for the .21 collection's amd64-static network-active benign tasks.
#
# Rationale: redesign's amd64-static "network" programs used loopback fixture services, not enp0s3, so they produce no
# captured traffic; its curl/wget are dynamic-linked. To give the amd64-static mode genuine Sink-network benign (and
# break the "any traffic = malware" shortcut there), build static curl/wget/openssl against musl for amd64.
#
# Sources: the authenticated, distribution-patched jammy source trees already used for the amd64 dynamic builds
# (cohort-100x100-v18-20261021/redesign-native-x64/builds/{openssl,curl,wget}-*-source), copied fresh. Toolchain:
# the authenticated musl-dev:amd64 and musl:amd64 1.2.2-4 binary packages (fetched through the workspace signed apt
# lists, which verify every file against the signed Packages index), plus the already-authenticated linux-libc-dev
# for kernel UAPI headers. Native /usr/bin/gcc compiles; nothing is installed system-wide and no maintainer script runs.
# musl avoids the guest-NSS crash seen with static glibc network tools. (Ubuntu jammy DOES ship musl:amd64, unlike i386.)
# Usage: build_amd64_network_tools.sh <output-dir>   (output dir must not exist)
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
redesign=$(cd -- "$here/../cohort-100x100-v18-20261021/redesign-native-x64" && pwd)
probe=$(cd -- "$here/../cohort-expansion-100x100-v18-20261021/i386-toolchain-probe/20261021T153000Z" && pwd)
out=${1:?output directory required}
[[ ! -e "$out" ]] || { echo "refusing to reuse $out" >&2; exit 2; }
mkdir -p "$out"/{debs,root,logs,src,prefix,bin}
out=$(cd -- "$out" && pwd)

apt_get() {
    apt-get -o Dir::Etc::main=- -o Dir::Etc::parts=- -o "Dir::Etc::sourcelist=$redesign/ubuntu-sources.list" \
        -o Dir::Etc::sourceparts=- -o "Dir::State::lists=$redesign/apt-lists" -o Dir::Cache::pkgcache= \
        -o Dir::Cache::srcpkgcache= -o Debug::NoLocking=true -o APT::Architectures::=amd64 "$@"
}

# 1. Toolchain: authenticated musl-dev/musl:amd64 binaries + the already-authenticated linux-libc-dev UAPI headers.
(cd "$out/debs" && apt_get download musl-dev:amd64 musl:amd64) > "$out/logs/download.log" 2>&1
cp "$probe/debs/linux-libc-dev_5.15.0-198.208_amd64.deb" "$out/debs/" 2>/dev/null \
  || (cd "$out/debs" && apt_get download linux-libc-dev:amd64 >> "$out/logs/download.log" 2>&1)
for package in "$out"/debs/*.deb; do dpkg-deb -x "$package" "$out/root"; done
(cd "$out/debs" && sha256sum ./*.deb) > "$out/package-sha256.txt"

musl_lib="$out/root/usr/lib/x86_64-linux-musl"
musl_inc="$out/root/usr/include/x86_64-linux-musl"
gcc_dir=$(dirname "$(/usr/bin/gcc -print-libgcc-file-name)")
uapi="$out/uapi"
gcc_include=$(/usr/bin/gcc -print-file-name=include)
mkdir -p "$uapi"
cp -a "$out/root/usr/include/linux" "$out/root/usr/include/asm-generic" "$uapi/" 2>/dev/null || true
cp -a "$out/root/usr/include/x86_64-linux-gnu/asm" "$uapi/asm" 2>/dev/null \
  || cp -a "$out/root/usr/include/asm" "$uapi/asm" 2>/dev/null || true
[[ -f "$musl_lib/libc.a" && -f "$musl_lib/crt1.o" && -d "$musl_inc" && -f "$gcc_dir/libgcc.a" ]] \
  || { echo "toolchain incomplete (musl_lib=$musl_lib)" >&2; ls -R "$out/root/usr/lib" | head -40 >&2; exit 3; }
file "$musl_lib/crt1.o" | grep -q "ELF 64-bit LSB relocatable, x86-64" || { echo "musl is not amd64" >&2; exit 3; }

cat > "$out/cc" <<EOF
#!/usr/bin/env bash
exec /usr/bin/gcc -m64 -nostdinc -nostdlib -static -isystem "$musl_inc" -isystem "$uapi" \\
    -isystem "$gcc_include" -B"$musl_lib" -B"$gcc_dir" -L"$musl_lib" -L"$gcc_dir" "\$@"
EOF
cat > "$out/ld-cc" <<EOF
#!/usr/bin/env bash
compile_only=0
for argument in "\$@"; do case "\$argument" in -c|-E|-S|-M|-MM) compile_only=1 ;; esac; done
if [[ \$compile_only == 1 ]]; then exec "$out/cc" "\$@"; fi
exec "$out/cc" "$musl_lib/crt1.o" "$musl_lib/crti.o" "$gcc_dir/crtbeginT.o" "\$@" \\
    -Wl,--start-group "$musl_lib/libc.a" "$gcc_dir/libgcc.a" "$gcc_dir/libgcc_eh.a" -Wl,--end-group \\
    "$gcc_dir/crtend.o" "$musl_lib/crtn.o"
EOF
chmod +x "$out/cc" "$out/ld-cc"
printf '#include <stdio.h>\nint main(void){puts("musl-amd64-ok");return 0;}\n' > "$out/logs/probe.c"
"$out/ld-cc" -O2 -o "$out/logs/probe" "$out/logs/probe.c" > "$out/logs/probe-build.log" 2>&1
"$out/logs/probe" | grep -qx musl-amd64-ok
export CC="$out/ld-cc" CFLAGS="-O2" LDFLAGS="" PKG_CONFIG_LIBDIR="$out/prefix/lib/pkgconfig" PKG_CONFIG_PATH=
host=x86_64-pc-linux-musl

copy_source() { cp -a "$redesign/builds/$1-source" "$out/src/$2"; }

# 2. OpenSSL (static library + the openssl CLI).
copy_source openssl-22b1c851fb5c openssl
(cd "$out/src/openssl" && ./Configure linux-x86_64 no-shared no-tests no-async no-afalgeng no-dso no-engine \
    --prefix="$out/prefix" --openssldir="$out/prefix/ssl" -DOPENSSL_NO_SECURE_MEMORY > "$out/logs/openssl-configure.log" 2>&1 \
    && make -j4 build_sw > "$out/logs/openssl-make.log" 2>&1 \
    && make install_dev > "$out/logs/openssl-install.log" 2>&1 \
    && cp apps/openssl "$out/bin/openssl")

# 3. curl with that OpenSSL.
copy_source curl-bfc41fccc801 curl
(cd "$out/src/curl" && ./configure --host=$host --disable-shared --enable-static --with-openssl="$out/prefix" \
    --without-libpsl --without-libidn2 --without-zlib --without-brotli --without-zstd --without-nghttp2 \
    --without-libssh2 --without-librtmp --disable-ldap --disable-ldaps --disable-manual --disable-threaded-resolver \
    > "$out/logs/curl-configure.log" 2>&1 \
    && make -j4 > "$out/logs/curl-make.log" 2>&1 && cp src/curl "$out/bin/curl")

# 4. wget without TLS (matches the amd64 dynamic/i386 builds).
copy_source wget-00b6acb233d5 wget
(cd "$out/src/wget" && ./configure --host=$host --without-ssl --without-libidn --without-gpgme --without-libpsl \
    --without-zlib --disable-pcre --disable-pcre2 --disable-nls --disable-iri > "$out/logs/wget-configure.log" 2>&1 \
    && make -j4 MAKEINFO=true > "$out/logs/wget-make.log" 2>&1 && cp src/wget "$out/bin/wget")

(cd "$out/bin" && sha256sum ./*) > "$out/binary-sha256.txt"
echo "built: $(ls "$out/bin" | tr '\n' ' ')"
