#!/usr/bin/env bash
set -euo pipefail

target="/tmp/ebpf-write-smoke-${PPID}-$$.txt"
printf 'successful eBPF write probe\n' >"$target"
test "$(cat "$target")" = "successful eBPF write probe"
rm -f "$target"