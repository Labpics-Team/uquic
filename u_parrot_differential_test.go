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

// Сохранённое наблюдение Chrome 149.0.7827.104 от 2026-06-17: relay capture
// перед cloudflare-quic.com, разобранный clienthellod — тем же parser, что здесь.
// Значения нормализованы и не чувствительны к порядку расширений/параметров.
// Это provenance исходного эталона, а не новый захват при каждом запуске теста.
//
// chrome149QUICNormHexID — нормализованный QUIC-ClientHello fingerprint
// clienthellod (NormHexID): ciphers + compression + сортированные extensions
// + groups + sigalgs + ALPN + keyshare + PSK-modes + supported-versions +
// cert-compress. Равенство сохранённому наблюдению не доказывает эквивалентность
// другой системе fingerprinting или правилам фильтрации конкретного оператора.
// Будущий выпуск браузера не меняет эти замороженные входы. Для проверки свежести
// нужен независимый новый захват; отдельные assertions ниже локализуют отклонение
// реализации относительно именно этого наблюдения.
const chrome149QUICNormHexID = "f82151be15528273"

// chrome149QUICTransportParamsHexID — отпечаток транспортных параметров
// clienthellod. Parser сортирует идентификаторы перед хешированием; этот
// результат не чувствителен к их порядку. Исходное наблюдение зафиксировало
// одинаковый результат двух захватов. Проверка относится к сохранённому
// отпечатку транспорта, который не покрывает TLS-ClientHello-сравнение.
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

// TestChrome146_DifferentialAgainstRealChrome сравнивает собранный библиотекой
// QUIC ClientHello с сохранённым нормализованным отпечатком и отдельными полями.
// Отдельные assertions локализуют отклонение, а не только сигнализируют смену
// хеша. Свежесть браузера и всё его сетевое поведение этот тест не устанавливает.
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

// TestChrome146_TransportParametersMatchRealChrome отдельно проверяет
// сохранённый отпечаток QUIC transport parameters. TLS-ClientHello-сравнение
// его не покрывает; сортировка идентификаторов не проверяет их порядок.
// Не вошедшие в хеш значения требуют отдельных assertions ниже.
func TestChrome146_TransportParametersMatchRealChrome(t *testing.T) {
	tp := dialParrotIntoClienthellod(t, QUICChrome_146).TransportParameters
	if tp.HexID != chrome149QUICTransportParamsHexID {
		t.Errorf("parrot QUIC transport-parameter fingerprint = %q, want real-Chrome-149 %q\n"+
			"transport-parameter IDs (sorted): %v", tp.HexID, chrome149QUICTransportParamsHexID, tp.QTPIDs)
	}
}

// TestChrome146_ExtensionOrderRandomizedPerSpecBuild проверяет конечную выборку
// новых спецификаций: наблюдается более одного порядка при неизменном
// нормализованном отпечатке. Это не гарантия разных порядков каждой пары
// соединений и не доказательство равномерности случайного распределения.
// Перемешивание выполняется при QUICID2Spec, не при повторном ApplyPreset;
// повторное использование спецификации проверяется отдельно ниже.
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

// TestChrome146_OrderFrozenWithinOneSpec сравнивает порядок расширений двух
// соединений с одной спецификацией. ApplyPreset использует уже построенный
// порядок, поэтому длительно живущий UTransport не означает новую перестановку.
// Проверка нормализованного отпечатка сама по себе не обнаружила бы этот эффект.
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

// TestChrome146_TransportParameterValuesMatchRealChrome закрепляет значения,
// которые не входят в TransportParameters.HexID: google_connection_options и
// max_datagram_frame_size. В исходном adversarial review замена ORIG на XXXX
// либо 65536 на 32768 не меняла предыдущий fingerprint-test; поэтому значения
// имеют отдельные assertions. Ожидаемые значения относятся к сохранённому
// наблюдению, не ко всем будущим версиям браузера.
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
