#!/usr/bin/env bash
# Build static i386 (musl) network clients for the .21 collection plan's network-active benign tasks.
#
# Sources: the authenticated, distribution-patched jammy source trees already used for the amd64 builds
# (cohort-100x100-v18-20261021/redesign-native-x64/builds/*-source; descriptors/archives verified there), copied fresh.
# Toolchain: musl 1.2.2 built for i386 from the jammy musl source package (fetched through the workspace's signed apt
# lists, which check every file against the signed Sources index; dpkg-source then only unpacks), plus the
# already-authenticated linux-libc-dev and lib32gcc-11-dev used by the earlier i386 builds. Host gcc -m32 compiles;
# nothing is installed system-wide and no maintainer script runs. musl avoids the guest-NSS crash seen with static
# glibc network tools. (Ubuntu jammy publishes no musl:i386 binary package.)
# Usage: build_i386_network_tools.sh <output-dir>   (output dir must not exist)
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
        -o Dir::Cache::srcpkgcache= -o Debug::NoLocking=true -o APT::Architectures::=amd64 -o APT::Architectures::=i386 "$@"
}

# 1. Toolchain. Ubuntu jammy publishes no musl:i386 binary, so musl is built for i386 from the authenticated jammy
#    musl source package (apt-get verifies the files against the signed Sources index). Kernel UAPI headers come from
#    the already-authenticated linux-libc-dev (its x86 asm headers cover i386 and x86_64); the 32-bit libgcc comes from
#    the already-authenticated lib32gcc-11-dev used by the earlier i386 builds.
cp "$probe/debs/linux-libc-dev_5.15.0-198.208_amd64.deb" "$probe/debs/lib32gcc-11-dev_11.4.0-1ubuntu1~22.04.3_amd64.deb" "$out/debs/"
for package in "$out"/debs/*.deb; do dpkg-deb -x "$package" "$out/root"; done
(cd "$out/src" && apt_get source --download-only musl) > "$out/logs/download.log" 2>&1
(cd "$out/src" && dpkg-source --no-check -x musl_*.dsc musl-src) > "$out/logs/musl-unpack.log" 2>&1
(cd "$out/debs" && sha256sum ./*.deb; cd "$out/src" && sha256sum musl_*.dsc musl_*.tar.*) > "$out/package-sha256.txt"
(cd "$out/src/musl-src" && ./configure --target=i386-linux-musl --prefix="$out/root/musl" --disable-shared \
    CC="/usr/bin/gcc -m32" CROSS_COMPILE= > "$out/logs/musl-configure.log" 2>&1 \
    && make -j4 AR=ar RANLIB=ranlib > "$out/logs/musl-make.log" 2>&1 \
    && make install AR=ar RANLIB=ranlib > "$out/logs/musl-install.log" 2>&1)
musl_lib="$out/root/musl/lib"
musl_inc="$out/root/musl/include"
gcc32="$out/root/usr/lib/gcc/x86_64-linux-gnu/11/32"
uapi="$out/uapi"
gcc_include=$(/usr/bin/gcc -print-file-name=include)
mkdir -p "$uapi"
cp -a "$out/root/usr/include/linux" "$out/root/usr/include/asm-generic" "$uapi/"
cp -a "$out/root/usr/include/x86_64-linux-gnu/asm" "$uapi/asm"
[[ -f "$musl_lib/libc.a" && -f "$musl_lib/crt1.o" && -d "$musl_inc" && -f "$gcc32/libgcc.a" ]] || { echo "toolchain incomplete" >&2; exit 3; }
file "$musl_lib/crt1.o" | grep -q "ELF 32-bit LSB relocatable, Intel 80386" || { echo "musl is not i386" >&2; exit 3; }

cat > "$out/cc" <<EOF
#!/usr/bin/env bash
exec /usr/bin/gcc -m32 -march=i686 -nostdinc -nostdlib -static -isystem "$musl_inc" -isystem "$uapi" \\
    -isystem "$gcc_include" -B"$musl_lib" -B"$gcc32" -L"$musl_lib" -L"$gcc32" "\$@"
EOF
# Link wrapper: musl crt objects, then the caller's objects/libs, then libc and libgcc.
cat > "$out/ld-cc" <<EOF
#!/usr/bin/env bash
compile_only=0
for argument in "\$@"; do case "\$argument" in -c|-E|-S|-M|-MM) compile_only=1 ;; esac; done
if [[ \$compile_only == 1 ]]; then exec "$out/cc" "\$@"; fi
exec "$out/cc" "$musl_lib/crt1.o" "$musl_lib/crti.o" "$gcc32/crtbeginT.o" "\$@" \\
    -Wl,--start-group "$musl_lib/libc.a" "$gcc32/libgcc.a" "$gcc32/libgcc_eh.a" -Wl,--end-group \\
    "$gcc32/crtend.o" "$musl_lib/crtn.o"
EOF
chmod +x "$out/cc" "$out/ld-cc"
printf '#include <stdio.h>\nint main(void){puts("musl-i386-ok");return 0;}\n' > "$out/logs/probe.c"
"$out/ld-cc" -O2 -o "$out/logs/probe" "$out/logs/probe.c" > "$out/logs/probe-build.log" 2>&1
"$out/logs/probe" | grep -qx musl-i386-ok
export CC="$out/ld-cc" CFLAGS="-O2" LDFLAGS="" PKG_CONFIG_LIBDIR="$out/prefix/lib/pkgconfig" PKG_CONFIG_PATH=
host=i686-pc-linux-musl

copy_source() { cp -a "$redesign/builds/$1-source" "$out/src/$2"; }

# 2. OpenSSL (static library + the openssl CLI).
copy_source openssl-22b1c851fb5c openssl
(cd "$out/src/openssl" && ./Configure linux-elf no-shared no-tests no-async no-afalgeng no-dso no-engine \
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

# 4. wget without TLS (as the amd64 build).
copy_source wget-00b6acb233d5 wget
(cd "$out/src/wget" && ./configure --host=$host --without-ssl --without-libidn --without-gpgme --without-libpsl \
    --without-zlib --disable-pcre --disable-pcre2 --disable-nls --disable-iri > "$out/logs/wget-configure.log" 2>&1 \
    && make -j4 MAKEINFO=true > "$out/logs/wget-make.log" 2>&1 && cp src/wget "$out/bin/wget")

# 5. inetutils clients.
copy_source inetutils-e96185e93be1 inetutils
(cd "$out/src/inetutils" && ./configure --host=$host --disable-servers --without-pam --disable-dependency-tracking \
    --disable-nls --disable-rcp --disable-rexec --disable-rlogin --disable-rsh --disable-talk --disable-ifconfig \
    > "$out/logs/inetutils-configure.log" 2>&1 \
    && make -j4 MAKEINFO=true > "$out/logs/inetutils-make.log" 2>&1 \
    && for program in ftp/ftp ping/ping src/traceroute telnet/telnet src/tftp whois/whois src/logger; do \
           [[ -f "$program" ]] && cp "$program" "$out/bin/"; done)

(cd "$out/bin" && sha256sum ./*) > "$out/binary-sha256.txt"
echo "built: $(ls "$out/bin" | tr '\n' ' ')"
