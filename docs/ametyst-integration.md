# uQUIC as the QUIC-fingerprint foundation for Ametyst

This note records the contract that the Ametyst integration depends on. It is
documentation only — it describes how this fork is consumed; it does not change
the parrot byte definitions or the dial path.

Epic: **Ametyst as Labpics overlay/exit — Phantom & Serverless integration.**

## What this fork provides

This is the Labpics fork of
[refraction-networking/uquic](https://github.com/refraction-networking/uquic), a
fork of [quic-go](https://github.com/quic-go/quic-go) that makes the unencrypted
QUIC Initial Packet (header, frames, and the TLS ClientHello inside it)
configurable so it can mimic a real browser's QUIC fingerprint. The presets are
the "parrots" in [`u_parrot.go`](../u_parrot.go), resolved by `QUICID2Spec`.

The parrot Ametyst rides on is `QUICChrome_146` — a Chrome QUIC fingerprint
byte-validated against a live Chrome capture (see the `QUICChrome_146` doc
comment and [`u_parrot_differential_test.go`](../u_parrot_differential_test.go),
which gates the normalized JA4_QUIC-equivalent fingerprint and the QUIC
transport-parameter fingerprint against a captured Chrome 149).

## Dependency direction

```
refraction-networking/uquic (this fork)   <-- QUIC Initial-Packet fingerprint
        |  imported by
        v
lemone112/vpn (Ametyst)                    <-- MASQUE transport / dial shim
        |  consumed by
        v
phantom & serverless integration consumers
```

The arrow is one-way. This fork knows nothing about Ametyst or its consumers; it
only exports parrots and a dial path. Ametyst's MASQUE transport reuses the
existing `UTransport.Dial` path with a resolved `QUICSpec` — **no functional
change to this fork is required** for the integration. The only Ametyst-facing
addition is a convenience accessor (below) so the shim need not hardcode a
version string.

## The parrot-freshness contract

A parrot is only useful while it matches a browser that is actually current on
the wire. **A stale browser version is itself a fingerprintable tell**: a client
claiming to be a Chrome that no real user still runs stands out as much as one
with a malformed ClientHello. Therefore:

- Only **current, byte-validated** browser parrots belong in the active set that
  consumers resolve. The active Chrome parrot is the one returned by
  `CurrentChromeParrot()`.
- Validation is enforced by the differential tests, which compare the parrot's
  reconstructed fingerprint (parsed by `clienthellod`) against captured ground
  truth from a real, current Chrome. If a future Chrome changes its QUIC
  ClientHello or transport parameters, those tests fail loudly — that failure is
  the freshness signal.
- Refreshing the parrot to a newer Chrome is a deliberate, reviewed change made
  **in lockstep**: update the parrot bytes, re-capture ground truth, update the
  differential test, and repoint `CurrentChromeParrot()`. The accessor gives the
  contract a single source of truth so a refresh here propagates to Ametyst
  without a code change there.
- Existing validated parrots (`QUICChrome_115`, `QUICFirefox_116`, …) are kept
  for reference and reproducibility; their **bytes are not to be modified** —
  re-validating an old version against a browser that has moved on would only
  weaken them.

### Consuming the current parrot

```go
spec, err := quic.QUICID2Spec(quic.CurrentChromeParrot())
```

`CurrentChromeParrot()` returns the `QUICID` of the currently validated Chrome
parrot (today `QUICChrome_146`). Consumers that want a specific, pinned version
may still name it directly (e.g. `quic.QUICChrome_146`); the accessor exists for
consumers that want to track "whatever is current and validated."

Note on extension/transport-parameter order: `QUICID2Spec` shuffles once per
call, and `ApplyPreset` copies that order verbatim, so a reused `UTransport`
presents a frozen order for its lifetime. Per-connection order variation
requires building the spec per connection — that is the rotation layer's
responsibility, not this fork's. JA4_QUIC sorts extensions, so order is
invisible to it regardless; the shuffle is fidelity against order-sensitive
(JA3-style) fingerprinting. See the differential test for the proof of both
halves.

## Research-grade disclaimer

This fork inherits uQUIC's status: it is **research-grade, not peer-reviewed and
not production-hardened** (see the [README disclaimer](../README.md#disclaimer)).
The mimicry **may not be realistically indistinguishable** from the real QUIC
client being mimicked, and the `QUICChrome_146` doc comment lists the known
residual-fidelity gaps (Initial-packet frame ordering is randomized rather than
Chrome's deterministic layout; `initial_rtt` is omitted). These are documented,
not faked. Anyone relying on this fingerprint for censorship circumvention must
understand those limits. Ametyst inherits this disclaimer — the fingerprint is a
best-effort foundation, not a guarantee.
