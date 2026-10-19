package quic

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/logging"
	tls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
)

// Получатель наблюдает фактическую UDP-датаграмму. Рукопожатие TLS не завершается:
// после первого Initial вызов отменяется, обе фоновые горутины завершаются.
func dialUTransportInitial(t *testing.T, spec *QUICSpec, conf *Config, early bool) (int, error) {
	t.Helper()
	server := newUPDConnLocalhost(t)
	client := newUPDConnLocalhost(t)
	transport := &UTransport{Transport: &Transport{Conn: client}, QUICSpec: spec}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), scaleDuration(3*time.Second))
	defer cancel()

	type readResult struct {
		size int
		err  error
	}
	packet := make(chan readResult, 1)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 65535)
		n, _, err := server.ReadFrom(buf)
		packet <- readResult{size: n, err: err}
	}()
	defer func() { server.Close(); <-readDone }()

	dialResult := make(chan error, 1)
	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		tlsConf := &tls.Config{ServerName: "localhost", NextProtos: []string{"h3"}}
		var err error
		if early {
			_, err = transport.DialEarly(ctx, server.LocalAddr(), tlsConf, conf)
		} else {
			_, err = transport.Dial(ctx, server.LocalAddr(), tlsConf, conf)
		}
		dialResult <- err
	}()
	defer func() { cancel(); <-dialDone }()

	select {
	case result := <-packet:
		require.NoError(t, result.err)
		return result.size, nil
	case err := <-dialResult:
		// После отказа проверяем и очередь сокета: ранний возврат Dial не
		// должен скрыть уже отправленную датаграмму.
		require.NoError(t, server.SetReadDeadline(time.Now().Add(scaleDuration(25*time.Millisecond))))
		result := <-packet
		if result.err == nil {
			return result.size, err
		}
		var netErr net.Error
		require.ErrorAs(t, result.err, &netErr)
		require.True(t, netErr.Timeout())
		return 0, err
	case <-ctx.Done():
		t.Fatal("neither Initial nor terminal dial result")
		return 0, ctx.Err()
	}
}

func TestUTransportInitialDatagramBudget(t *testing.T) {
	for _, early := range []bool{false, true} {
		t.Run(fmt.Sprintf("early=%t", early), func(t *testing.T) {
			for _, tc := range []struct {
				name      string
				id        QUICID
				conf      *Config
				minimum   int
				wantSize  int
				wantError string
			}{
				{name: "firefox_a_nil", id: QUICFirefox_116A, wantSize: 1357},
				{name: "firefox_b_nil", id: QUICFirefox_116B, wantSize: 1357},
				{name: "firefox_c_nil", id: QUICFirefox_116C, wantSize: 1357},
				{name: "firefox_empty", id: QUICFirefox_116A, conf: &Config{}, wantSize: 1357},
				{name: "firefox_explicit_matching", id: QUICFirefox_116A, conf: &Config{InitialPacketSize: 1357}, wantSize: 1357},
				{name: "firefox_explicit_larger", id: QUICFirefox_116A, conf: &Config{InitialPacketSize: 1452}, wantSize: 1357},
				{name: "firefox_explicit_default", id: QUICFirefox_116A, conf: &Config{InitialPacketSize: 1280}, wantError: "exceeds budget 1280"},
				{name: "firefox_explicit_smaller", id: QUICFirefox_116A, conf: &Config{InitialPacketSize: 1200}, wantError: "exceeds budget 1200"},
				{name: "profile_at_supported_maximum", id: QUICFirefox_116A, minimum: protocol.MaxPacketBufferSize, wantSize: protocol.MaxPacketBufferSize},
				{name: "ordinary_nil", wantSize: 1280},
				{name: "ordinary_explicit", conf: &Config{InitialPacketSize: 1200}, wantSize: 1200},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var spec *QUICSpec
					var originalMinimum int
					if tc.id != (QUICID{}) {
						value, err := QUICID2Spec(tc.id)
						require.NoError(t, err)
						spec = &value
						if tc.minimum != 0 {
							spec.UDPDatagramMinSize = tc.minimum
						}
						originalMinimum = spec.UDPDatagramMinSize
					}
					var originalConfig *Config
					if tc.conf != nil {
						originalConfig = tc.conf.Clone()
					}
					size, err := dialUTransportInitial(t, spec, tc.conf, early)
					if tc.wantError == "" {
						require.NoError(t, err)
					} else {
						require.ErrorContains(t, err, tc.wantError)
					}
					require.Equal(t, tc.wantSize, size)
					require.Equal(t, originalConfig, tc.conf, "default normalization mutated caller configuration")
					if spec != nil {
						require.Equal(t, originalMinimum, spec.UDPDatagramMinSize, "dial mutated the shared profile")
					}
				})
			}
		})
	}
}

func TestUTransportRejectsUnsupportedInitialDatagramSize(t *testing.T) {
	for _, minimum := range []int{protocol.MaxPacketBufferSize + 1, (1 << 16) + 1357} {
		t.Run(fmt.Sprint(minimum), func(t *testing.T) {
			spec, err := QUICID2Spec(QUICFirefox_116A)
			require.NoError(t, err)
			spec.UDPDatagramMinSize = minimum
			started := false
			conf := &Config{Tracer: func(context.Context, logging.Perspective, ConnectionID) *logging.ConnectionTracer {
				started = true
				return nil
			}}
			size, err := dialUTransportInitial(t, &spec, conf, false)
			require.ErrorContains(t, err, fmt.Sprintf("minimum datagram size %d exceeds maximum datagram budget %d", minimum, protocol.MaxPacketBufferSize))
			require.Zero(t, size)
			require.False(t, started, "unsupported profile must fail before connection construction")
			require.Zero(t, conf.InitialPacketSize)
			require.Equal(t, minimum, spec.UDPDatagramMinSize)
		})
	}
}
