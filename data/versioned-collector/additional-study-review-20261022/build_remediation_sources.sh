#!/usr/bin/env bash
set -euo pipefail

attempt=${1:?Usage: build_remediation_sources.sh ATTEMPT PROJECT}
project=${2:?Project required}
revision=${3:-}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
native="$root/../cohort-100x100-v18-20261021/redesign-native-x64"
source "$native/build-tool-env.sh"
dependencies="$attempt/dependencies/root"
export PATH="$dependencies/usr/bin:$PATH"
export C_INCLUDE_PATH="$dependencies/usr/include:$C_INCLUDE_PATH"
export LIBRARY_PATH="$dependencies/usr/lib/x86_64-linux-gnu:$LIBRARY_PATH"
export LD_LIBRARY_PATH="$dependencies/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$dependencies/usr/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH"
tree="$attempt/trees/$project"
build="$attempt/builds/$project${revision:+-$revision}"
if [[ -n "$revision" ]]; then
    tree="$attempt/trees/$project-$revision"
    descriptors=("$attempt/sources/$project/"*.dsc)
    [[ ${#descriptors[@]} == 1 ]]
    dpkg-source -x "${descriptors[0]}" "$tree"
fi
mkdir -p "$attempt/builds"
mkdir "$build"
cd "$build"
case "$project" in
    libarchive)
        pushd "$tree" > /dev/null
        autoreconf -fi
        popd > /dev/null
        "$tree/configure" --disable-shared --enable-static --without-xml2 --without-expat --without-openssl --without-nettle --without-lzo2 --without-lz4 --without-zstd --without-lzma --without-bz2lib --without-zlib --disable-bsdcpio --disable-bsdcat
        make -j2 bsdtar
        ;;
    perl)
        cp -a "$tree/." "$build/"
        bash Configure -des -Dprefix="$build/install" -Dman1dir=none -Dman3dir=none -Uuseshrplib -Dcc=cc -Doptimize=-O2
        make -j2 perl
        ;;
    imagemagick)
        pushd "$tree" > /dev/null
        autoreconf -fi
        popd > /dev/null
        "$tree/configure" --disable-shared --enable-static --disable-openmp --without-modules --without-perl --without-x --without-magick-plus-plus --with-utilities --without-bzlib --without-djvu --without-dps --without-fftw --without-fpx --without-fontconfig --without-freetype --without-gslib --without-gvc --without-jbig --without-jpeg --without-jp2 --without-lcms --without-lqr --without-lzma --without-openexr --without-pango --without-png --without-raqm --without-tiff --without-webp --without-wmf --without-xml --without-zlib
        make -j2 utilities/convert
        ;;
    netcat-openbsd)
        cp -a "$tree/." "$build/"
        make -j2 CC=cc "CFLAGS=-g -O2 -I$dependencies/usr/include" "LIBS=$dependencies/usr/lib/x86_64-linux-gnu/libbsd.a $dependencies/usr/lib/x86_64-linux-gnu/libmd.a -lresolv"
        ;;
    *) printf 'Unsupported approved project: %s\n' "$project" >&2; exit 2 ;;
esac