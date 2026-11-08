#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ -d "$root/build-tools/root/usr/bin" ]]; then
    source "$root/build-tool-env.sh"
fi
project=${1:?Usage: bash prepare_benign_source.sh PROJECT [fetch|static|dynamic]}
mode=${2:-fetch}
case "$project" in
    coreutils|diffutils|findutils|sed|grep|gzip|tar|patch|ed|gawk|make-dfsg|cpio|binutils|util-linux|bzip2|xz-utils|procps|psmisc|curl|wget|openssl|jq|rsync|less|nano|libzstd|zip|unzip|inetutils|git) ;;
    *) printf 'Unsupported source project: %s\n' "$project" >&2; exit 2 ;;
esac
case "$mode" in
    fetch|static|dynamic) ;;
    *) printf 'Unsupported build mode: %s\n' "$mode" >&2; exit 2 ;;
esac

apt_options=(
    -o Dir::Etc::main=- -o Dir::Etc::parts=-
    -o "Dir::Etc::sourcelist=$root/ubuntu-sources.list"
    -o Dir::Etc::sourceparts=- -o "Dir::State::lists=$root/apt-lists"
    -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache=
    -o Debug::NoLocking=true
)
source_root="$root/benign-sources/$project"
mkdir -p "$source_root" "$root/builds" "$root/logs"
cd "$source_root"
apt-get "${apt_options[@]}" source --only-source --download-only "$project" > "$root/logs/$project-download.log" 2>&1 || {
    tail -n 60 "$root/logs/$project-download.log" >&2
    exit 1
}
mapfile -t descriptors < <(find "$source_root" -maxdepth 1 -type f -name '*.dsc' | sort)
if [[ ${#descriptors[@]} -ne 1 ]]; then
    printf 'Expected one pinned source descriptor, found %s\n' "${#descriptors[@]}" >&2
    exit 1
fi
sha256sum "$root"/apt-lists/*InRelease "${descriptors[0]}" > "$source_root/authentication.sha256"
if [[ "$mode" == fetch ]]; then
    printf 'Authenticated source downloaded: %s\n' "$project"
    exit 0
fi
case "$project" in
    coreutils|diffutils|findutils|sed|grep|gzip|tar|patch|ed|gawk|make-dfsg|cpio|binutils|util-linux|bzip2|zip|unzip|git|libzstd|openssl|inetutils|procps|psmisc|curl|wget|rsync|jq|less|nano|xz-utils) ;;
    *) printf 'Source fetched; build recipe not yet validated for %s\n' "$project" >&2; exit 2 ;;
esac

source_digest=$(sha256sum "${descriptors[0]}")
source_digest=${source_digest%% *}
tree="$root/builds/$project-${source_digest:0:12}-source"
build="$root/builds/$project-${source_digest:0:12}-$mode"
if [[ ${HAZIM_COMPAT_LIBC:-0} == 1 ]]; then
    if [[ "$mode" != static || ! "$project" =~ ^(inetutils|procps)$ ]]; then
        printf 'Compatible-libc build is restricted to static inetutils/procps\n' >&2
        exit 2
    fi
    export CC="bash $root/prepare_compatible_static.sh --cc"
    if [[ "$project" == procps ]]; then
        export CPPFLAGS="-D__UT_HOSTSIZE=256 -D__UT_NAMESIZE=32 -D__UT_LINESIZE=32 -include langinfo.h"
        export PKG_CONFIG_PATH="$root/compatible-static/musl-root/usr/lib/pkgconfig"
        export PKG_CONFIG_LIBDIR="$PKG_CONFIG_PATH"
    fi
    build+="-guest-libc"
fi
if [[ "$project" == gawk ]]; then
    tree="$root/builds/$project-${source_digest:0:12}-binary-source"
fi
if [[ ! -d "$tree" ]]; then
    dpkg-source -x "${descriptors[0]}" "$tree" > "$root/logs/$project-unpack.log" 2>&1 || {
        tail -n 60 "$root/logs/$project-unpack.log" >&2
        exit 1
    }
fi
if [[ "$project" =~ ^(util-linux|grep|sed|gzip|patch|inetutils|procps|psmisc|tar|curl|wget|rsync|jq|nano|xz-utils)$ && ! -f "$tree/.local-autoreconf-complete" ]]; then
    pushd "$tree" > /dev/null
    autoreconf -fi > "$root/logs/$project-autoreconf.log" 2>&1 || {
        tail -n 80 "$root/logs/$project-autoreconf.log" >&2
        exit 1
    }
    printf 'autoreconf -fi\n' > .local-autoreconf-complete
    popd > /dev/null
fi
mkdir -p "$build"
cd "$build"
ldflags=
if [[ "$mode" == static ]]; then
    ldflags=-static
fi
if [[ "$project" =~ ^(bzip2|zip|unzip|git|libzstd|openssl|rsync)$ ]]; then
    if [[ "$project" != bzip2 && "$mode" != dynamic ]]; then
        printf 'Only the planned dynamic recipe is supported for %s\n' "$project" >&2
        exit 2
    fi
    cp -a "$tree/." "$build/"
    rm -f "$build/build-success.sha256"
    {
        printf 'project=%s\nmode=%s\nsource_descriptor=%s\nsource_tree=%s\nLDFLAGS=%s\n' "$project" "$mode" "${descriptors[0]}" "$tree" "$ldflags"
        cc --version
    } > "$build/build-provenance.txt"
    case "$project" in
        bzip2) make_command=(make -j2 "CFLAGS=-O2 $ldflags" "LDFLAGS=$ldflags" libbz2.a bzip2.o bzip2recover) ;;
        zip|unzip) make_command=(make -f unix/Makefile generic CC=cc) ;;
        git)
            make hook-list.h > "$root/logs/$project-$mode-generated.log" 2>&1
            make_command=(make -j2 NO_GETTEXT=YesPlease NO_TCLTK=YesPlease NO_PERL=YesPlease NO_PYTHON=YesPlease NO_CURL=YesPlease NO_OPENSSL=YesPlease git git-shell git-daemon)
            ;;
        libzstd) make_command=(make -C programs -j2 zstd) ;;
        rsync)
            env LDFLAGS="$ldflags" ./configure --disable-xxhash --disable-lz4 --disable-zstd --disable-openssl --disable-md2man > "$root/logs/$project-$mode-configure.log" 2>&1
            make_command=(make -j2 rsync)
            ;;
        openssl)
            perl Configure linux-x86_64 no-shared no-tests > "$root/logs/$project-$mode-configure.log" 2>&1
            make_command=(make -j2 build_sw)
            ;;
    esac
    printf 'make_command=%q ' "${make_command[@]}" >> "$build/build-provenance.txt"
    printf '\n' >> "$build/build-provenance.txt"
    "${make_command[@]}" > "$root/logs/$project-$mode-make.log" 2>&1 || {
        tail -n 60 "$root/logs/$project-$mode-make.log" >&2
        exit 1
    }
    if [[ "$project" == bzip2 ]]; then
        cc $ldflags -o bzip2 bzip2.o libbz2.a >> "$root/logs/$project-$mode-make.log" 2>&1
        printf 'final_link_command=cc %s -o bzip2 bzip2.o libbz2.a\n' "$ldflags" >> "$build/build-provenance.txt"
    fi
    sha256sum "${descriptors[0]}" "$build/build-provenance.txt" > "$build/build-success.sha256"
    printf 'Built benign source: %s (%s) at %s\n' "$project" "$mode" "$build"
    exit 0
fi
configure_options=(--disable-nls --disable-dependency-tracking)
if [[ "$project" == coreutils ]]; then
    configure_options+=(--without-gmp --without-libcap --without-libacl --without-selinux)
elif [[ "$project" == binutils ]]; then
    configure_options+=(--disable-gdb --disable-gdbserver --disable-gprofng --disable-gold --disable-shared --disable-werror --without-debuginfod)
elif [[ "$project" == util-linux ]]; then
    configure_options+=(--disable-shared --enable-static --without-systemd --without-selinux --without-udev --without-python --disable-makeinstall-chown --disable-makeinstall-setuid)
elif [[ "$project" == inetutils ]]; then
    configure_options+=(--disable-servers --enable-inetd --without-pam)
elif [[ "$project" == procps ]]; then
    configure_options+=(--without-systemd --disable-shared --enable-static)
elif [[ "$project" == psmisc ]]; then
    configure_options+=(--disable-selinux --disable-apparmor)
elif [[ "$project" == curl ]]; then
    configure_options+=(--with-openssl --without-libidn2 --without-libpsl --disable-shared --enable-static)
elif [[ "$project" == wget ]]; then
    configure_options+=(--without-ssl --without-libidn --without-gpgme)
elif [[ "$project" == rsync ]]; then
    configure_options+=(--disable-xxhash --disable-lz4 --disable-zstd --disable-openssl)
elif [[ "$project" == jq ]]; then
    configure_options+=(--without-oniguruma --disable-docs --disable-maintainer-mode --disable-shared --enable-static)
elif [[ "$project" == xz-utils ]]; then
    configure_options+=(--disable-shared --enable-static)
fi
{
    printf 'project=%s\nmode=%s\nsource_descriptor=%s\nLDFLAGS=%s\n' "$project" "$mode" "${descriptors[0]}" "$ldflags"
    if [[ ${HAZIM_COMPAT_LIBC:-0} == 1 ]]; then
        printf 'runtime_target=musl-static-no-guest-nss-plugins\nCC=%s\n' "$CC"
        sha256sum "$root/compatible-static/musl-package-sha256.txt" "$root/prepare_compatible_static.sh"
    fi
    cc --version
    printf 'configure_option=%s\n' "${configure_options[@]}"
} > "$build/build-provenance.txt"
env LDFLAGS="$ldflags" "$tree/configure" "${configure_options[@]}" > "$root/logs/$project-$mode-configure.log" 2>&1 || {
    tail -n 60 "$root/logs/$project-$mode-configure.log" >&2
    exit 1
}
rm -f "$build/build-success.sha256"
if [[ "$project" == jq ]]; then
    mkdir -p "$build/src"
fi
make_options=(-j2 MAKEINFO=true)
if [[ "$project" == curl ]]; then
    make clean > "$root/logs/$project-$mode-clean.log" 2>&1
fi
if [[ "$project" == gawk ]]; then
    make -C support -j2 MAKEINFO=true > "$root/logs/$project-$mode-support.log" 2>&1 || {
        tail -n 60 "$root/logs/$project-$mode-support.log" >&2
        exit 1
    }
    make_options+=(gawk)
fi
if [[ ( "$project" == util-linux || "$project" == procps ) && "$mode" == static ]]; then
    make clean > "$root/logs/$project-$mode-clean.log" 2>&1
    make_options+=(LDFLAGS=-all-static)
fi
printf 'make_option=%s\n' "${make_options[@]}" >> "$build/build-provenance.txt"
make "${make_options[@]}" > "$root/logs/$project-$mode-make.log" 2>&1 || {
    tail -n 80 "$root/logs/$project-$mode-make.log" >&2
    exit 1
}
if [[ "$project" == binutils && "$mode" == static ]]; then
    printf 'final_program_link_mode=-all-static\n' >> "$build/build-provenance.txt"
    for program_dir in binutils gas ld gprof; do
        make -C "$program_dir" clean >> "$root/logs/$project-$mode-relink.log" 2>&1
        make -C "$program_dir" -j2 MAKEINFO=true LDFLAGS=-all-static >> "$root/logs/$project-$mode-relink.log" 2>&1 || {
            tail -n 80 "$root/logs/$project-$mode-relink.log" >&2
            exit 1
        }
    done
fi
sha256sum "${descriptors[0]}" "$build/build-provenance.txt" > "$build/build-success.sha256"
printf 'Built benign source: %s (%s) at %s\n' "$project" "$mode" "$build"