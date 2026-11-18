# Go environment for building labtransport: everything inside this folder, no telemetry, the local toolchain only.
T21="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export GOROOT="$T21/../committee-eval-20261113/toolchain/benign-build/toolchains/go/go1.24.13/go"
export PATH="$GOROOT/bin:$PATH"
export GOPATH="$T21/.gopath" GOMODCACHE="$T21/.gopath/pkg/mod" GOCACHE="$T21/.gocache"
export HOME="$T21/.home" XDG_CONFIG_HOME="$T21/.home/.config"
export GOTELEMETRY=off GOTOOLCHAIN=local GOFLAGS=-mod=mod CGO_ENABLED=0
