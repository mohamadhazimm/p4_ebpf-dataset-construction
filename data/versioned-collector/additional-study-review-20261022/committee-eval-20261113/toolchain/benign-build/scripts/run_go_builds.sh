#!/usr/bin/env bash
# Build the benign Go programs with every downloaded Go release (see build_go.py). Usage: run_go_builds.sh <benign-build dir>
set -u
BB=$1
ur() { local v=$1; local s="github.com/u-root/u-root@$v:"; local first=1
  for c in md5sum shasum base64 gzip sort uniq wc hexdump cmp tar cat; do
    [[ $first == 1 ]] || s+=","; first=0; s+="github.com/u-root/u-root/cmds/core/$c=$c"; done; echo "$s"; }
jq() { echo "github.com/itchyny/gojq@$1:github.com/itchyny/gojq/cmd/gojq=gojq"; }
xh() { echo "github.com/cespare/xxhash/v2@$1:github.com/cespare/xxhash/v2/xxhsum=xxhsum-go"; }
xz() { echo "github.com/ulikunitz/xz@$1:github.com/ulikunitz/xz/cmd/gxz=gxz"; }
b() { taskset -c 12-23 nice -n 19 /usr/bin/python3 -I "$BB/scripts/build_go.py" "$BB" "$@"; }
b go1.13.15 "$(ur v0.1.0)" "$(jq v0.12.4)" "$(xh v2.1.2)" "$(xz v0.5.11)"
b go1.16.15 "$(ur v0.8.0)" "$(jq v0.12.5)" "$(xh v2.1.2)" "$(xz v0.5.11)"
b go1.18.10 "$(ur v0.10.0)" "$(jq v0.12.13)" "$(xh v2.2.0)" "$(xz v0.5.11)"
b go1.20.14 "$(ur v0.11.0)" "$(jq v0.12.13)" "$(xh v2.2.0)" "$(xz v0.5.11)"
b go1.21.13 "$(ur v0.12.0)" "$(jq v0.12.17)" "$(xh v2.3.0)" "$(xz v0.5.12)"
b go1.22.12 "$(ur v0.14.0)" "$(jq v0.12.17)" "$(xh v2.3.0)" "$(xz v0.5.12)"
b go1.24.13 "$(ur v0.16.0)" "$(jq v0.12.20)" "$(xh v2.3.0)" "$(xz v0.5.15)"
