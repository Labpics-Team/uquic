package quic

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/refraction-networking/clienthellod"
	tls "github.com/refraction-networking/utls"
)

// Ground truth captured from a real Chrome 149.0.7827.104 QUIC handshake on
// 2026-06-17 (relay capture in front of cloudflare-quic.com, parsed by
// clienthellod — the same parser used here). These are order-INSENSITIVE
// (normalized) values, so they are stable across Chrome's per-connection
// extension/transport-parameter shuffling.
//
// chrome149QUICNormHexID is clienthellod's normalized QUIC-ClientHello
// fingerprint (NormHexID): a hash over ciphers + compression + SORTED extensions
// + groups + sigalgs + ALPN + keyshare + PSK-modes + supported-versions +
// cert-compress. Because it sorts extensions it is JA4_QUIC-equivalent in
// normalization, which is what Russia's TSPU filters on. If a future Chrome
// changes its QUIC ClientHello this fails loudly — the freshness signal ch15
// exists to provide. The decomposed fields below are asserted too, so a failure
// names the culprit instead of only flipping an opaque hash.
const chrome149QUICNormHexID = "f82151be15528273"

var (
	chrome149QUICNormalizedExtensions = []uint16{0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 65037}
	chrome149QUICCipherSuites         = []uint16{4865, 4866, 4867}
	chrome149QUICSupportedGroups      = []uint16{4588, 29, 23, 24} // X25519MLKEM768, X25519, P256, P384
	chrome149QUICKeyShareGroups       = []uint16{4588, 29}         // X25519MLKEM768, X25519
	chrome149QUICSignatureSchemes     = []uint16{1027, 2052, 1025, 1283, 2053, 1281, 2054, 1537, 513}
)

func equalU16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// dialSpecIntoClienthellod dials the given (already-built) QUICSpec at a local
// clienthellod listener and returns the reconstructed QUIC ClientHello. The
// listener never answers, so the handshake never completes — but the parrot
// emits its full Initial flight immediately, which is all clienthellod needs.
//
// Passing a *pre-built* spec is deliberate: ShuffleChromeTLSExtensions runs once
// inside QUICID2Spec, and ApplyPreset copies the resulting order verbatim, so a
// reused spec yields a frozen extension order (see TestChrome146_OrderFrozenWithinOneSpec).
func dialSpecIntoClienthellod(t *testing.T, spec *QUICSpec) *clienthellod.QUICClientHello {
	t.Helper()

	lconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lconn.Close()
	port := lconn.LocalAddr().(*net.UDPAddr).Port

	deadline := time.Now().Add(8 * time.Second)
	gci := clienthellod.GatherClientInitialsWithDeadline(deadline)
	stopCh := make(chan struct{})
	listenerDone := make(chan struct{})

	go func() {
		defer close(listenerDone)
		buf := make([]byte, 65535)
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			_ = lconn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, _, rerr := lconn.ReadFromUDP(buf)
			if rerr != nil {
				if gci.Completed() || time.Now().After(deadline) {
					return
				}
				continue
			}
			d := make([]byte, n)
			copy(d, buf[:n])
			ci, perr := clienthellod.UnmarshalQUICClientInitialPacket(d)
			if perr != nil {
				continue
			}
			_ = gci.AddPacket(ci)
			if gci.Completed() {
				return
			}
		}
	}()

	pktConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("pktConn: %v", err)
	}
	defer pktConn.Close()
	tr := &UTransport{Transport: &Transport{Conn: pktConn}, QUICSpec: spec}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		_, _ = tr.Dial(ctx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
			&tls.Config{ServerName: "cloudflare-quic.com", NextProtos: []string{"h3"}},
			&Config{})
	}()

	werr := gci.Wait()
	cancel()         // CH captured (or timed out): stop the dial
	<-dialDone       // dial goroutine returns before deferred Close (leak detector)
	close(stopCh)    // and the listener goroutine too, before lconn.Close
	<-listenerDone
	if werr != nil {
		t.Fatalf("clienthellod did not reconstruct the parrot ClientHello: %v", werr)
	}
	if gci.ClientHello == nil {
		t.Fatal("gathered initials completed but ClientHello is nil")
	}
	return gci.ClientHello
}

// dialParrotIntoClienthellod builds a FRESH spec (fresh shuffle) and dials it.
func dialParrotIntoClienthellod(t *testing.T, id QUICID) *clienthellod.QUICClientHello {
	t.Helper()
	spec, err := QUICID2Spec(id)
	if err != nil {
		t.Fatalf("QUICID2Spec(%v): %v", id, err)
	}
	return dialSpecIntoClienthellod(t, &spec)
}

// TestChrome146_DifferentialAgainstRealChrome is the load-bearing fidelity gate:
// the parrot's QUIC ClientHello, packed by uQUIC and parsed by clienthellod, must
// reproduce the IDENTICAL normalized fingerprint AND decomposed fields as a real
// captured Chrome 149. An imperfect parrot is worse than none ("parrot is dead"),
// so this is a hard gate. Asserting the decomposed fields (not just the opaque
// hash) means a regression names the culprit.
func TestChrome146_DifferentialAgainstRealChrome(t *testing.T) {
	ch := dialParrotIntoClienthellod(t, QUICChrome_146)

	if ch.NormHexID != chrome149QUICNormHexID {
		t.Errorf("parrot normalized fingerprint = %q, want real-Chrome-149 %q", ch.NormHexID, chrome149QUICNormHexID)
	}
	if !equalU16(ch.ExtensionsNormalized, chrome149QUICNormalizedExtensions) {
		t.Errorf("normalized extensions = %v, want %v", ch.ExtensionsNormalized, chrome149QUICNormalizedExtensions)
	}
	if !equalU16(ch.CipherSuites, chrome149QUICCipherSuites) {
		t.Errorf("cipher suites = %v, want %v", ch.CipherSuites, chrome149QUICCipherSuites)
	}
	if !equalU16(ch.NamedGroupList, chrome149QUICSupportedGroups) {
		t.Errorf("supported groups = %v, want %v", ch.NamedGroupList, chrome149QUICSupportedGroups)
	}
	if !equalU16(ch.KeyShare, chrome149QUICKeyShareGroups) {
		t.Errorf("key_share groups = %v, want %v", ch.KeyShare, chrome149QUICKeyShareGroups)
	}
	if !equalU16(ch.SignatureSchemeList, chrome149QUICSignatureSchemes) {
		t.Errorf("signature schemes = %v, want %v", ch.SignatureSchemeList, chrome149QUICSignatureSchemes)
	}
	if len(ch.ALPN) != 1 || ch.ALPN[0] != "h3" {
		t.Errorf("alpn = %v, want [h3]", ch.ALPN)
	}
}

// TestChrome146_ExtensionOrderRandomizedPerSpecBuild proves the per-build half of
// Chrome's order-shuffle: each QUICID2Spec call shuffles afresh, so building the
// spec per connection yields a different extension order per connection (the
// raw, order-sensitive fingerprint varies) while the normalized fingerprint stays
// constant. RED proof: with a hardcoded (un-shuffled) slice the raw IDs collapse
// to one value and this fails.
//
// NOTE: this is what makes per-connection variation POSSIBLE; it is not automatic.
// ShuffleChromeTLSExtensions runs once per QUICID2Spec and ApplyPreset copies the
// order verbatim, so the rotation layer must build the spec per connection to get
// per-connection order variation — see TestChrome146_OrderFrozenWithinOneSpec.
func TestChrome146_ExtensionOrderRandomizedPerSpecBuild(t *testing.T) {
	const builds = 6
	rawIDs := make(map[string]struct{})
	for i := 0; i < builds; i++ {
		ch := dialParrotIntoClienthellod(t, QUICChrome_146) // fresh spec each iteration
		if ch.NormHexID != chrome149QUICNormHexID {
			t.Fatalf("build %d: normalized fingerprint drifted to %q, want %q", i, ch.NormHexID, chrome149QUICNormHexID)
		}
		rawIDs[ch.HexID] = struct{}{}
	}
	if len(rawIDs) < 2 {
		t.Errorf("raw (order-sensitive) fingerprint never varied across %d fresh spec builds (%v) — extensions are not being shuffled", builds, rawIDs)
	}
}

// TestChrome146_OrderFrozenWithinOneSpec documents the flip side, so the property
// is tested rather than assumed: a single spec reused across connections presents
// the SAME extension order every time (ShuffleChromeTLSExtensions shuffled once at
// build, ApplyPreset copies verbatim). This is why a long-lived UTransport keeps a
// frozen order and the rotation layer must build the spec per connection. The
// normalized fingerprint is identical either way, and JA4_QUIC sorts extensions,
// so this freeze does not change the JA4 a censor matches.
func TestChrome146_OrderFrozenWithinOneSpec(t *testing.T) {
	spec, err := QUICID2Spec(QUICChrome_146)
	if err != nil {
		t.Fatalf("QUICID2Spec: %v", err)
	}
	first := dialSpecIntoClienthellod(t, &spec).Extensions
	second := dialSpecIntoClienthellod(t, &spec).Extensions
	if !equalU16(first, second) {
		t.Errorf("same spec produced different extension orders across dials: %v vs %v\n"+
			"(expected frozen order; if Chrome's shuffle is meant to be per-connection, build the spec per connection)", first, second)
	}
}
