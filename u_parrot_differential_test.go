package quic

import (
	"bytes"
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

// chrome149QUICTransportParamsHexID is clienthellod's QUIC transport-parameter
// fingerprint (TransportParameters.HexID). clienthellod sorts the parameter IDs
// before hashing, so it is order-insensitive and stable across Chrome's
// per-connection transport-parameter shuffle (verified: identical across two
// independent captures). This gates the QUIC-transport-layer fingerprint, which
// the TLS-ClientHello differential above does NOT cover.
const chrome149QUICTransportParamsHexID = "2f750907435c203d"

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
// clienthellod listener and returns the reconstructed gathered initials (TLS
// ClientHello + QUIC transport parameters). The listener never answers, so the
// handshake never completes — but the parrot emits its full Initial flight
// immediately, which is all clienthellod needs.
//
// Passing a *pre-built* spec is deliberate: ShuffleChromeTLSExtensions runs once
// inside QUICID2Spec, and ApplyPreset copies the resulting order verbatim, so a
// reused spec yields a frozen extension order (see TestChrome146_OrderFrozenWithinOneSpec).
func dialSpecIntoClienthellod(t *testing.T, spec *QUICSpec) *clienthellod.GatheredClientInitials {
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
	cancel()      // CH captured (or timed out): stop the dial
	<-dialDone    // dial goroutine returns before deferred Close (leak detector)
	close(stopCh) // and the listener goroutine too, before lconn.Close
	<-listenerDone
	if werr != nil {
		t.Fatalf("clienthellod did not reconstruct the parrot ClientHello: %v", werr)
	}
	if gci.ClientHello == nil {
		t.Fatal("gathered initials completed but ClientHello is nil")
	}
	if gci.TransportParameters == nil {
		t.Fatal("gathered initials completed but TransportParameters is nil")
	}
	return gci
}

// dialParrotIntoClienthellod builds a FRESH spec (fresh shuffle) and dials it.
func dialParrotIntoClienthellod(t *testing.T, id QUICID) *clienthellod.GatheredClientInitials {
	t.Helper()
	spec, err := QUICID2Spec(id)
	if err != nil {
		t.Fatalf("QUICID2Spec(%v): %v", id, err)
	}
	return dialSpecIntoClienthellod(t, &spec)
}

// TestChrome146_DifferentialAgainstRealChrome is the load-bearing TLS-fidelity
// gate: the parrot's QUIC ClientHello, packed by uQUIC and parsed by clienthellod,
// must reproduce the IDENTICAL normalized fingerprint AND decomposed fields as a
// real captured Chrome 149. An imperfect parrot is worse than none ("parrot is
// dead"), so this is a hard gate. Asserting the decomposed fields (not just the
// opaque hash) means a regression names the culprit.
func TestChrome146_DifferentialAgainstRealChrome(t *testing.T) {
	ch := dialParrotIntoClienthellod(t, QUICChrome_146).ClientHello

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

// TestChrome146_TransportParametersMatchRealChrome gates the QUIC transport-
// parameter fingerprint, which the TLS-ClientHello differential does not cover.
// JA4_QUIC keys on the TLS ClientHello only, but a censor doing QUIC-transport-
// parameter fingerprinting would distinguish a mismatched parrot — so for true
// Chrome fidelity the transport parameters must match too. clienthellod sorts the
// parameter IDs before hashing, so this fingerprint is order-insensitive.
func TestChrome146_TransportParametersMatchRealChrome(t *testing.T) {
	tp := dialParrotIntoClienthellod(t, QUICChrome_146).TransportParameters
	if tp.HexID != chrome149QUICTransportParamsHexID {
		t.Errorf("parrot QUIC transport-parameter fingerprint = %q, want real-Chrome-149 %q\n"+
			"transport-parameter IDs (sorted): %v", tp.HexID, chrome149QUICTransportParamsHexID, tp.QTPIDs)
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
		ch := dialParrotIntoClienthellod(t, QUICChrome_146).ClientHello // fresh spec each iteration
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
	first := dialSpecIntoClienthellod(t, &spec).ClientHello.Extensions
	second := dialSpecIntoClienthellod(t, &spec).ClientHello.Extensions
	if !equalU16(first, second) {
		t.Errorf("same spec produced different extension orders across dials: %v vs %v\n"+
			"(expected frozen order; if Chrome's shuffle is meant to be per-connection, build the spec per connection)", first, second)
	}
}

// TestChrome146_TransportParameterValuesMatchRealChrome locks the transport-
// parameter VALUES that clienthellod's TransportParameters.HexID does NOT hash.
// That fingerprint hashes the values of only the standard RFC parameters plus the
// sorted set of ALL parameter IDs — so a value-only drift in
// google_connection_options or max_datagram_frame_size would slip past
// TestChrome146_TransportParametersMatchRealChrome (verified by adversarial
// review: changing "ORIG"->"XXXX" or 65536->32768 left that test green). These two
// are Chrome-specific values — google_connection_options was historically mis-set
// to "B2ON"/"RVCM" before the correct "ORIG" — so they get a direct regression
// guard at the spec level.
func TestChrome146_TransportParameterValuesMatchRealChrome(t *testing.T) {
	spec, err := QUICID2Spec(QUICChrome_146)
	if err != nil {
		t.Fatalf("QUICID2Spec: %v", err)
	}
	var qtp *tls.QUICTransportParametersExtension
	for _, e := range spec.ClientHelloSpec.Extensions {
		if q, ok := e.(*tls.QUICTransportParametersExtension); ok {
			qtp = q
			break
		}
	}
	if qtp == nil {
		t.Fatal("QUICChrome_146 has no QUICTransportParametersExtension")
	}
	byID := make(map[uint64]tls.TransportParameter, len(qtp.TransportParameters))
	for _, p := range qtp.TransportParameters {
		byID[p.ID()] = p
	}

	// google_connection_options (0x3128) must carry "ORIG" (real Chrome 149).
	const googleConnectionOptions = 0x3128
	if g, ok := byID[googleConnectionOptions]; !ok {
		t.Errorf("google_connection_options (0x3128) is absent")
	} else if !bytes.Equal(g.Value(), []byte("ORIG")) {
		t.Errorf("google_connection_options = %q, want %q", g.Value(), "ORIG")
	}

	// max_datagram_frame_size (0x20) must encode 65536 (real Chrome 149).
	const maxDatagramFrameSize = 0x20
	if d, ok := byID[maxDatagramFrameSize]; !ok {
		t.Errorf("max_datagram_frame_size (0x20) is absent")
	} else if want := tls.MaxDatagramFrameSize(65536).Value(); !bytes.Equal(d.Value(), want) {
		t.Errorf("max_datagram_frame_size value = %v, want %v (65536)", d.Value(), want)
	}
}
