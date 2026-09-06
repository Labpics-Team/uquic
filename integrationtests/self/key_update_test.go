package self_test

import (
	"context"
	"flag"
	"io"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	quic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/internal/handshake"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/logging"

	"github.com/stretchr/testify/require"
)

var isolatedKeyUpdates = flag.Bool("quic-key-update-process", false, "запустить только изолированный stress-test обновления ключей")

func TestKeyUpdates(t *testing.T) {
	const selection = "^TestKeyUpdates$"
	const completed = "key-update assertions completed"
	if !*isolatedKeyUpdates {
		// Другие тесты могут ещё завершать соединения. Глобальная тестовая настройка
		// принадлежит отдельному процессу, а не временно меняется в общем адресном
		// пространстве. Исполняется тот же бинарь: -race и GOARCH сохраняются.
		executable, err := os.Executable()
		require.NoError(t, err)
		ctx := context.Background()
		if deadline, ok := t.Deadline(); ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}
		args := []string{
			"-test.run=" + selection, "-test.v", "-test.count=1",
			"-quic-key-update-process",
			"-version=" + flag.Lookup("version").Value.String(),
			"-qlog=" + strconv.FormatBool(enableQlog),
		}
		if deadline, ok := t.Deadline(); ok {
			args = append(args, "-test.timeout="+time.Until(deadline).String())
		}
		// GSO/ECN и TIMESCALE_FACTOR наследуются без изменения.
		output, err := exec.CommandContext(ctx, executable, args...).CombinedOutput()
		t.Logf("isolated key-update process:\n%s", output)
		require.NoError(t, err)
		// Нулевой exit при отсутствии выбранного теста не является доказательством.
		require.Contains(t, string(output), completed)
		return
	}
	require.Equal(t, selection, flag.Lookup("test.run").Value.String())
	handshake.KeyUpdateInterval = 1 // Восстановление не нужно: процесс владеет настройкой до выхода.

	var sentHeaders []*logging.ShortHeader
	var receivedHeaders []*logging.ShortHeader

	countKeyPhases := func() (sent, received int) {
		lastKeyPhase := protocol.KeyPhaseOne
		for _, hdr := range sentHeaders {
			if hdr.KeyPhase != lastKeyPhase {
				sent++
				lastKeyPhase = hdr.KeyPhase
			}
		}
		lastKeyPhase = protocol.KeyPhaseOne
		for _, hdr := range receivedHeaders {
			if hdr.KeyPhase != lastKeyPhase {
				received++
				lastKeyPhase = hdr.KeyPhase
			}
		}
		return
	}

	server, err := quic.Listen(newUPDConnLocalhost(t), getTLSConfig(), nil)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(
		ctx,
		newUPDConnLocalhost(t),
		server.Addr(),
		getTLSClientConfig(),
		getQuicConfig(&quic.Config{Tracer: func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
			return &logging.ConnectionTracer{
				SentShortHeaderPacket: func(hdr *logging.ShortHeader, _ logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
					sentHeaders = append(sentHeaders, hdr)
				},
				ReceivedShortHeaderPacket: func(hdr *logging.ShortHeader, _ logging.ByteCount, _ logging.ECN, _ []logging.Frame) {
					receivedHeaders = append(receivedHeaders, hdr)
				},
			}
		}}),
	)
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	serverErrChan := make(chan error, 1)
	go func() {
		str, err := serverConn.OpenUniStream()
		if err != nil {
			serverErrChan <- err
			return
		}
		defer str.Close()
		if _, err := str.Write(PRDataLong); err != nil {
			serverErrChan <- err
			return
		}
		close(serverErrChan)
	}()

	str, err := conn.AcceptUniStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRDataLong, data)
	require.NoError(t, conn.CloseWithError(0, ""))

	require.NoError(t, <-serverErrChan)

	keyPhasesSent, keyPhasesReceived := countKeyPhases()
	t.Logf("Used %d key phases on outgoing and %d key phases on incoming packets.", keyPhasesSent, keyPhasesReceived)
	require.Greater(t, keyPhasesReceived, 10)
	require.InDelta(t, keyPhasesSent, keyPhasesReceived, 2)
	t.Log(completed)
}
