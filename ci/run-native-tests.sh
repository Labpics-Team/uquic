#!/usr/bin/env bash
set -euo pipefail

# Each native job supplies typed matrix values. Flags and protocol switches
# belong to this invocation, rather than mutable state shared between steps.
race=${QUIC_CI_RACE:-false}
use32bit=${QUIC_CI_32BIT:-false}
debug=${DEBUG:-false}
for value in "$race" "$use32bit" "$debug"; do
  case "$value" in true|false) ;; *) echo "invalid CI boolean: $value" >&2; exit 1;; esac
done

unset GOOS GOARCH QUIC_GO_DISABLE_GSO QUIC_GO_DISABLE_ECN
export GOFLAGS='' GOENV=off
if [ "$use32bit" = true ]; then export GOARCH=386; fi
args=(test -count=1 -v -shuffle=on)
if [ "$race" = true ]; then args+=(-race); fi

case "${1:-}" in
  self)
    version=${QUIC_CI_VERSION:?missing QUIC version}
    case "$version" in 1|2) ;; *) echo 'invalid QUIC version' >&2; exit 1;; esac
    case "${QUIC_CI_MODE:-}" in
      v1|v2) ;;
      gso) export QUIC_GO_DISABLE_GSO=true;;
      ecn) export QUIC_GO_DISABLE_ECN=true;;
      *) echo 'invalid QUIC mode' >&2; exit 1;;
    esac
    args+=(-timeout 5m ./integrationtests/self "-version=$version")
    if [ "$debug" = true ]; then args+=(-qlog); fi;;
  tools) args+=(-timeout 30s ./integrationtests/tools/...);;
  versionnegotiation)
    args+=(-timeout 30s ./integrationtests/versionnegotiation)
    if [ "$debug" = true ]; then args+=(-qlog); fi;;
  benchmarks) args+=(-timeout 5m '-run=^$' '-bench=.' ./integrationtests/self);;
  *) echo 'unknown native test suite' >&2; exit 1;;
esac
go "${args[@]}"
