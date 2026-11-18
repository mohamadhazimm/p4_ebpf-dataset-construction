#!/bin/bash
# B runs of the sensor-visibility test: unpack one sample and start it detached, with the dataset's launch wrapper
# (bash exec, standard input from /dev/null, own session), then exit. Nothing else of ours runs in the guest while the
# sample runs; packets are recorded outside the guest by VirtualBox.
#   start.sh SAMPLE_ZIP WORK_DIR [ARGUMENTS...]
set -u
zip="$1"
work="$2"
shift 2
mkdir -p "$work/x" || exit 2
cd "$work" || exit 2
/usr/bin/7z x -pinfected -o"$work/x" -y "$zip" >"$work/.extract.log" 2>&1 || exit 3
exe="$(find "$work/x" -type f | head -n 1)"
[ -n "$exe" ] || exit 4
chmod +x "$exe" || exit 5
date +%s.%N >"$work/.started"
setsid /bin/bash -c 'exec "$@"' sample-launch "$exe" "$@" </dev/null >"$work/.out" 2>"$work/.err" &
echo "$!" >"$work/.pid"
exit 0
