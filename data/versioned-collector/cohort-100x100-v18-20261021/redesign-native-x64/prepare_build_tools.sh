#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$root/build-tools/debs" "$root/build-tools/root"
cd "$root/build-tools/debs"
apt-get \
    -o Dir::Etc::main=- -o Dir::Etc::parts=- \
    -o "Dir::Etc::sourcelist=$root/ubuntu-sources.list" \
    -o Dir::Etc::sourceparts=- -o "Dir::State::lists=$root/apt-lists" \
    -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= \
    -o Debug::NoLocking=true \
    download autoconf autoconf-archive automake autotools-dev autopoint pkg-config gtk-doc-tools m4 libtool libtool-bin libltdl-dev libgpgme-dev libgpg-error-dev libassuan-dev \
    bison flex gettext gettext-base libncurses-dev libreadline-dev libpopt-dev \
    libpopt0 libssl-dev zlib1g-dev libbz2-dev liblzma-dev libpcre2-dev \
    libpcre2-8-0 libpcre2-posix3 libsigsegv-dev libsigsegv2
for package in ./*.deb; do
    dpkg-deb -x "$package" "$root/build-tools/root"
done
sha256sum ./*.deb > "$root/build-tools/package-sha256.txt"
prefix="$root/build-tools/root"
while IFS= read -r -d '' tool_file; do
    sed -i \
        -e "s|^prefix=/usr$|prefix=$prefix/usr|" \
        -e "s|/usr/share/autoconf|$prefix/usr/share/autoconf|g" \
        -e "s|/usr/share/automake-1.16|$prefix/usr/share/automake-1.16|g" \
        -e "s|/usr/share/aclocal|$prefix/usr/share/aclocal|g" \
        -e "s|/usr/share/libtool|$prefix/usr/share/libtool|g" \
        -e "s|/usr/share/bison|$prefix/usr/share/bison|g" \
        -e "s|/usr/share/gettext|$prefix/usr/share/gettext|g" \
        -e "s|/usr/share/gtk-doc|$prefix/usr/share/gtk-doc|g" \
        -e "s|/usr/bin/m4|$prefix/usr/bin/m4|g" \
        "$tool_file"
done < <(grep -rlIZ -E '/usr/share/(autoconf|automake-1.16|aclocal|libtool|bison|gettext|gtk-doc)|/usr/bin/m4|^prefix=/usr$' "$prefix/usr/bin" "$prefix/usr/share")
printf 'Build prerequisites extracted under %s\n' "$root/build-tools/root"