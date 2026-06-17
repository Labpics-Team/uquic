package quic

import (
	"context"
	"net"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
)

func testDialPanic(t *testing.T, id QUICID) {

	quicSpec, err := QUICID2Spec(id)
	if err != nil {
		t.Fatal(err)
	}

	pktConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}

	tr := &UTransport{Transport: &Transport{Conn: pktConn}, QUICSpec: &quicSpec}
	// Close the transport so its background goroutines exit; otherwise the
	// package-level leak detector in TestMain reports stray transport goroutines.
	defer tr.Close()
	defer pktConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tr.Dial(ctx, &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 1234}, &tls.Config{}, &Config{})

}

func TestDialPanic(t *testing.T) {

	for _, s := range []QUICID{QUICChrome_115, QUICFirefox_116, QUICChrome_146} {
		testDialPanic(t, s)
	}

}

// TestQUICID2Spec_Chrome146 locks the invariants the Chrome 146 parrot must satisfy:
// a spec is returned without error, its ClientHelloSpec carries a
// QUICTransportParametersExtension (without it u_connection.go panics at runtime), and
// that extension actually holds transport parameters. It also confirms the spec
// round-trips through a second QUICID2Spec call.
func TestQUICID2Spec_Chrome146(t *testing.T) {
	spec, err := QUICID2Spec(QUICChrome_146)
	if err != nil {
		t.Fatalf("QUICID2Spec(QUICChrome_146) returned error: %v", err)
	}

	if spec.ClientHelloSpec == nil {
		t.Fatal("QUICChrome_146 spec has a nil ClientHelloSpec")
	}
	if spec.InitialPacketSpec.FrameBuilder == nil {
		t.Fatal("QUICChrome_146 spec has a nil InitialPacketSpec.FrameBuilder")
	}

	var qtp *tls.QUICTransportParametersExtension
	for _, ext := range spec.ClientHelloSpec.Extensions {
		if e, ok := ext.(*tls.QUICTransportParametersExtension); ok {
			qtp = e
			break
		}
	}
	if qtp == nil {
		t.Fatal("QUICChrome_146 ClientHelloSpec is missing a *tls.QUICTransportParametersExtension; u_connection.go would panic")
	}
	if len(qtp.TransportParameters) == 0 {
		t.Fatal("QUICChrome_146 QUICTransportParametersExtension carries no transport parameters")
	}

	// Round-trip: a second resolution must also succeed and keep the QTP invariant.
	spec2, err := QUICID2Spec(QUICChrome_146)
	if err != nil {
		t.Fatalf("second QUICID2Spec(QUICChrome_146) returned error: %v", err)
	}
	hasQTP := false
	for _, ext := range spec2.ClientHelloSpec.Extensions {
		if _, ok := ext.(*tls.QUICTransportParametersExtension); ok {
			hasQTP = true
			break
		}
	}
	if !hasQTP {
		t.Fatal("round-trip QUICChrome_146 spec lost its QUICTransportParametersExtension")
	}
}
