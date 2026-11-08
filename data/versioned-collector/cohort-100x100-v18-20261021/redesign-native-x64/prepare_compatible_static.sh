#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
target="$root/compatible-static"
version=2.43-2ubuntu2.4
if [[ ${1:-} == --cc ]]; then
    shift
    unset C_INCLUDE_PATH
    exec /usr/bin/cc -specs="$target/musl-root/usr/lib/x86_64-linux-musl/musl-gcc.specs" \
        -L"$target/musl-root/usr/lib" -I"$target/musl-root/usr/include" \
        -I"$target/musl-root/usr/include/ncurses" "$@"
fi
if [[ ${1:-} == --musl ]]; then
    mkdir -p "$target/musl-debs" "$target/musl-root" "$target/logs"
    cd "$target/musl-debs"
    apt-get -o Dir::Etc::main=- -o Dir::Etc::parts=- \
        -o "Dir::Etc::sourcelist=$root/ubuntu-sources.list" -o Dir::Etc::sourceparts=- \
        -o "Dir::State::lists=$root/apt-lists" -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= \
        -o Debug::NoLocking=true download musl musl-dev musl-tools > "$target/logs/musl-download.log" 2>&1
    for package in ./*.deb; do
        dpkg-deb -x "$package" "$target/musl-root"
    done
    sha256sum ./*.deb > "$target/musl-package-sha256.txt"
    sed -i "s|/usr/lib/x86_64-linux-musl|$target/musl-root/usr/lib/x86_64-linux-musl|g; s|/usr/include/x86_64-linux-musl|$target/musl-root/usr/include/x86_64-linux-musl|g; s|/lib/ld-musl-x86_64.so.1|$target/musl-root/lib/x86_64-linux-musl/libc.so|g" \
        "$target/musl-root/usr/lib/x86_64-linux-musl/musl-gcc.specs"
    bash "$root/prepare_compatible_static.sh" --cc -O2 -static "$root/payload/nss_diagnostic.c" \
        -o "$target/nss-diagnostic-musl" > "$target/logs/musl-probe-build.log" 2>&1
    exit 0
fi
if [[ ${1:-} == --ncurses ]]; then
    mkdir -p "$target/ncurses-archives" "$target/ncurses-build" "$target/musl-root/usr/lib/pkgconfig"
    cd "$target/ncurses-archives"
    apt-get -o Dir::Etc::main=- -o Dir::Etc::parts=- \
        -o "Dir::Etc::sourcelist=$root/ubuntu-sources.list" -o Dir::Etc::sourceparts=- \
        -o "Dir::State::lists=$root/apt-lists" -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= \
        -o Debug::NoLocking=true source --only-source --download-only ncurses > "$target/logs/ncurses-download.log" 2>&1
    if [[ ! -d "$target/ncurses-source" ]]; then
        dpkg-source -x ./*.dsc "$target/ncurses-source" > "$target/logs/ncurses-unpack.log" 2>&1
    fi
    cd "$target/ncurses-build"
    CC="bash $root/prepare_compatible_static.sh --cc" "$target/ncurses-source/configure" \
        --prefix="$target/musl-root/usr" --without-shared --without-cxx --without-cxx-binding \
        --without-ada --without-tests --without-progs --with-termlib --enable-pc-files \
        --with-terminfo-dirs=/etc/terminfo:/lib/terminfo:/usr/share/terminfo \
        --with-pkg-config-libdir="$target/musl-root/usr/lib/pkgconfig" > "$target/logs/ncurses-configure.log" 2>&1
    make -j2 > "$target/logs/ncurses-make.log" 2>&1
    make install > "$target/logs/ncurses-install.log" 2>&1
    sha256sum "$target"/ncurses-archives/* > "$target/ncurses-source-sha256.txt"
    exit 0
fi
mkdir -p "$target/apt-lists/partial" "$target/debs" "$target/sysroot" "$target/logs"
printf '%s\n' \
    'deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu resolute main' \
    'deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu resolute-updates main' \
    'deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://security.ubuntu.com/ubuntu resolute-security main' > "$target/ubuntu-sources.list"
apt_options=(
    -o Dir::Etc::main=- -o Dir::Etc::parts=-
    -o "Dir::Etc::sourcelist=$target/ubuntu-sources.list" -o Dir::Etc::sourceparts=-
    -o "Dir::State::lists=$target/apt-lists" -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=
    -o Debug::NoLocking=true -o Acquire::Languages=none
)
apt-get "${apt_options[@]}" update > "$target/logs/apt-update.log" 2>&1
cd "$target/debs"
apt-get "${apt_options[@]}" download "libc6-dev=$version" "libc6=$version" "libc-dev-bin=$version" linux-libc-dev > "$target/logs/download.log" 2>&1
for package in ./*.deb; do
    dpkg-deb -x "$package" "$target/sysroot"
done
sha256sum ./*.deb > "$target/package-sha256.txt"
for release in "$target"/apt-lists/*InRelease; do
    gpgv --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg "$release" >> "$target/logs/signatures.log" 2>&1
done
sha256sum "$target"/apt-lists/*InRelease > "$target/release-sha256.txt"
cc --sysroot="$target/sysroot" -B"$target/sysroot/usr/lib/x86_64-linux-gnu/" -O2 -static \
    "$root/payload/nss_diagnostic.c" -o "$target/nss-diagnostic-compatible" > "$target/logs/probe-build.log" 2>&1
readelf -l "$target/nss-diagnostic-compatible" > "$target/logs/probe-elf.txt"
if grep -q INTERP "$target/logs/probe-elf.txt"; then
    printf 'Compatibility probe unexpectedly has an interpreter\n' >&2
    exit 1
fi
sha256sum "$target/nss-diagnostic-compatible" "$root/payload/nss_diagnostic.c" > "$target/probe-sha256.txt"
printf 'Prepared authenticated glibc %s static probe under %s\n' "$version" "$target"