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
// clienthellod — the same parser used here). These are the order-INSENSITIVE
// (normalized) values, so they are stable across Chrome's per-connection
// extension/transport-parameter shuffling.
//
// The normalized ClientHello fingerprint is exactly what JA4_QUIC keys on (it
// sorts extensions), and JA4 is the fingerprint Russia's TSPU is known to filter
// on. If a future Chrome changes its QUIC ClientHello, this test fails loudly —
// which is the freshness signal ch15 exists to provide.
const (
	chrome149QUICNormHexID = "f82151be15528273"
)

var chrome149QUICNormalizedExtensions = []uint16{0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 65037}

// dialParrotIntoClienthellod dials the given parrot at a local clienthellod
// listener and returns the reconstructed QUIC ClientHello. The listener never
// answers, so the handshake never completes — but the parrot emits its full
// Initial flight immediately, which is all clienthellod needs.
func dialParrotIntoClienthellod(t *testing.T, id QUICID) *clienthellod.QUICClientHello {
	t.Helper()

	lconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lconn.Close()
	port := lconn.LocalAddr().(*net.UDPAddr).Port

	deadline := time.Now().Add(8 * time.Second)
	gci := clienthellod.GatherClientInitialsWithDeadline(deadline)

	go func() {
		buf := make([]byte, 65535)
		for {
			_ = lconn.SetReadDeadline(time.Now().Add(time.Second))
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

	spec, err := QUICID2Spec(id)
	if err != nil {
		t.Fatalf("QUICID2Spec(%v): %v", id, err)
	}
	pktConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("pktConn: %v", err)
	}
	defer pktConn.Close()
	tr := &UTransport{Transport: &Transport{Conn: pktConn}, QUICSpec: &spec}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	// Dial never succeeds (no server); the Initial flight is sent immediately, so
	// run it in the background and stop as soon as clienthellod has the ClientHello.
	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		_, _ = tr.Dial(ctx, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
			&tls.Config{ServerName: "cloudflare-quic.com", NextProtos: []string{"h3"}},
			&Config{})
	}()

	werr := gci.Wait()
	cancel()     // CH captured (or timed out): stop the dial
	<-dialDone   // let the dial goroutine return before deferred Close (leak detector)
	if werr != nil {
		t.Fatalf("clienthellod did not reconstruct the parrot ClientHello: %v", werr)
	}
	if gci.ClientHello == nil {
		t.Fatal("gathered initials completed but ClientHello is nil")
	}
	return gci.ClientHello
}

// TestChrome146_DifferentialAgainstRealChrome is the load-bearing fidelity gate:
// the parrot's QUIC ClientHello, packed by uQUIC and parsed by clienthellod, must
// produce the IDENTICAL normalized fingerprint as a real captured Chrome 149.
// An imperfect parrot is worse than none ("parrot is dead"), so this is a hard gate.
func TestChrome146_DifferentialAgainstRealChrome(t *testing.T) {
	ch := dialParrotIntoClienthellod(t, QUICChrome_146)

	if ch.NormHexID != chrome149QUICNormHexID {
		t.Errorf("parrot normalized JA4-QUIC fingerprint = %q, want real-Chrome-149 %q\n"+
			"parrot normalized extensions: %v", ch.NormHexID, chrome149QUICNormHexID, ch.ExtensionsNormalized)
	}

	if len(ch.ExtensionsNormalized) != len(chrome149QUICNormalizedExtensions) {
		t.Fatalf("parrot has %d normalized extensions %v, want %d %v",
			len(ch.ExtensionsNormalized), ch.ExtensionsNormalized,
			len(chrome149QUICNormalizedExtensions), chrome149QUICNormalizedExtensions)
	}
	for i, want := range chrome149QUICNormalizedExtensions {
		if ch.ExtensionsNormalized[i] != want {
			t.Errorf("normalized extension[%d] = %d, want %d (full: %v)",
				i, ch.ExtensionsNormalized[i], want, ch.ExtensionsNormalized)
		}
	}
}

// TestChrome146_ShufflesExtensionOrder proves the parrot reproduces Chrome's
// per-connection extension-order shuffle: the normalized fingerprint is constant,
// but the raw (order-sensitive) fingerprint varies across connections. A fixed
// order would itself be a static tell. RED proof: with a hardcoded (un-shuffled)
// extension slice, the raw IDs are identical every dial and this test fails.
func TestChrome146_ShufflesExtensionOrder(t *testing.T) {
	const dials = 6
	rawIDs := make(map[string]struct{})
	for i := 0; i < dials; i++ {
		ch := dialParrotIntoClienthellod(t, QUICChrome_146)
		if ch.NormHexID != chrome149QUICNormHexID {
			t.Fatalf("dial %d: normalized fingerprint drifted to %q, want %q", i, ch.NormHexID, chrome149QUICNormHexID)
		}
		rawIDs[ch.HexID] = struct{}{}
	}
	if len(rawIDs) < 2 {
		t.Errorf("raw (order-sensitive) fingerprint never varied across %d dials (%v) — extensions are not being shuffled", dials, rawIDs)
	}
}
