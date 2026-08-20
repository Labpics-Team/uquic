package quic

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/refraction-networking/uquic/internal/handshake"
	"github.com/refraction-networking/uquic/internal/mocks"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/utils"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestMaxDatagramPayloadSizeTracksCurrentMTU(t *testing.T) {
	for _, tc := range []struct {
		mtu  protocol.ByteCount
		want protocol.ByteCount
	}{
		{mtu: 1200, want: 1156},
		{mtu: 1280, want: 1236},
		{mtu: 1452, want: 1408},
	} {
		require.Equal(t, tc.want, maxDatagramPayloadSize(wire.MaxDatagramSize, tc.mtu, protocol.Version1))
	}
}

func TestMaxDatagramPayloadSizeReturnsZeroWithoutPeerSupport(t *testing.T) {
	require.Zero(t, maxDatagramPayloadSize(0, 1200, protocol.Version1))
	require.Zero(t, maxDatagramPayloadSize(protocol.InvalidByteCount, 1200, protocol.Version1))
	require.Zero(t, maxDatagramPayloadSize(1, 1200, protocol.Version1))
}

func TestSendDatagramRejectsWithoutUsablePeerSupport(t *testing.T) {
	for _, peerMaxFrameSize := range []protocol.ByteCount{
		protocol.InvalidByteCount,
		0,
		1,
	} {
		conn := &connection{
			version:       protocol.Version1,
			datagramQueue: newDatagramQueue(func() {}, utils.DefaultLogger, 0),
		}
		conn.setPeerTransportParameters(&wire.TransportParameters{MaxDatagramFrameSize: peerMaxFrameSize})
		require.EqualError(t, conn.SendDatagram(nil), "datagram support disabled")
	}
}

func TestMaxDatagramPayloadSizeHonorsPeerFrameLimit(t *testing.T) {
	const peerMaxFrameSize = protocol.ByteCount(100)
	frame := &wire.DatagramFrame{DataLenPresent: true}
	require.Equal(
		t,
		frame.MaxDataLen(peerMaxFrameSize, protocol.Version1),
		maxDatagramPayloadSize(peerMaxFrameSize, 1200, protocol.Version1),
	)
}

func TestMaxDatagramPayloadSizeDoesNotUnderflow(t *testing.T) {
	require.Zero(t, maxDatagramPayloadSize(wire.MaxDatagramSize, 0, protocol.Version1))
	require.Zero(t, maxDatagramPayloadSize(wire.MaxDatagramSize, 41, protocol.Version1))
}

func TestSendDatagramRejectsPayloadAboveConservativePacketBudget(t *testing.T) {
	const (
		mtu     = protocol.ByteCount(1200)
		wantMax = protocol.ByteCount(1156)
	)
	conn := &connection{
		version:       protocol.Version1,
		datagramQueue: newDatagramQueue(func() {}, utils.DefaultLogger, 0),
	}
	conn.setCurrentMTUEstimate(mtu)
	conn.setPeerTransportParameters(&wire.TransportParameters{MaxDatagramFrameSize: wire.MaxDatagramSize})

	require.NoError(t, conn.SendDatagram(make([]byte, wantMax)))
	require.Len(t, conn.datagramQueue.Peek().Data, int(wantMax))
	conn.datagramQueue.Pop()

	err := conn.SendDatagram(make([]byte, wantMax+1))
	var sizeErr *DatagramTooLargeError
	require.ErrorAs(t, err, &sizeErr)
	require.Equal(t, int64(wantMax), sizeErr.MaxDatagramPayloadSize)
	require.Nil(t, conn.datagramQueue.Peek())
}

func TestDatagramCapabilityIsConsistentDuringTransportParameterReplacement(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cryptoSetup := mocks.NewMockCryptoSetup(mockCtrl)
	cryptoSetup.EXPECT().ConnectionState().Return(handshake.ConnectionState{}).AnyTimes()
	tc := newClientTestConnection(
		t,
		mockCtrl,
		&Config{EnableDatagrams: true, DisablePathMTUDiscovery: true},
		false,
		connectionOptCryptoSetup(cryptoSetup),
	)
	tc.conn.setCurrentMTUEstimate(1200)

	enabled := &wire.TransportParameters{
		InitialSourceConnectionID:       tc.destConnID,
		OriginalDestinationConnectionID: tc.destConnID,
		MaxDatagramFrameSize:            wire.MaxDatagramSize,
	}
	disabled := &wire.TransportParameters{
		InitialSourceConnectionID:       tc.destConnID,
		OriginalDestinationConnectionID: tc.destConnID,
		MaxDatagramFrameSize:            1,
	}
	require.NoError(t, tc.conn.handleTransportParameters(enabled))

	const iterations = 1000
	start := make(chan struct{})
	errCh := make(chan error, 1)
	recordErr := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			params := enabled
			if i%2 == 0 {
				params = disabled
			}
			if err := tc.conn.handleTransportParameters(params); err != nil {
				recordErr(fmt.Errorf("replace transport parameters: %w", err))
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			state := tc.conn.ConnectionState()
			switch {
			case state.SupportsDatagrams && state.MaxDatagramPayloadSize != 1156:
				recordErr(fmt.Errorf("supported DATAGRAM snapshot published max %d", state.MaxDatagramPayloadSize))
				return
			case !state.SupportsDatagrams && state.MaxDatagramPayloadSize != 0:
				recordErr(fmt.Errorf("disabled DATAGRAM snapshot published max %d", state.MaxDatagramPayloadSize))
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		payload := make([]byte, 20_000)
		for i := 0; i < iterations; i++ {
			err := tc.conn.SendDatagram(payload)
			if err == nil {
				recordErr(errors.New("oversized DATAGRAM was accepted"))
				return
			}
			var sizeErr *DatagramTooLargeError
			if errors.As(err, &sizeErr) && sizeErr.MaxDatagramPayloadSize != 1156 {
				recordErr(fmt.Errorf("oversized DATAGRAM observed max %d", sizeErr.MaxDatagramPayloadSize))
				return
			}
		}
	}()
	close(start)
	wg.Wait()
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

func TestBlockedSendDatagramUsesFinalTransportParameters(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cryptoSetup := mocks.NewMockCryptoSetup(mockCtrl)
	cryptoSetup.EXPECT().ConnectionState().Return(handshake.ConnectionState{}).AnyTimes()
	tc := newClientTestConnection(
		t,
		mockCtrl,
		&Config{EnableDatagrams: true, DisablePathMTUDiscovery: true},
		false,
		connectionOptCryptoSetup(cryptoSetup),
	)
	tc.conn.setCurrentMTUEstimate(1200)
	t.Cleanup(func() { tc.conn.datagramQueue.CloseWithError(errors.New("test cleanup")) })

	enabled := &wire.TransportParameters{
		InitialSourceConnectionID:       tc.destConnID,
		OriginalDestinationConnectionID: tc.destConnID,
		MaxDatagramFrameSize:            wire.MaxDatagramSize,
	}
	disabled := &wire.TransportParameters{
		InitialSourceConnectionID:       tc.destConnID,
		OriginalDestinationConnectionID: tc.destConnID,
		MaxDatagramFrameSize:            1,
	}
	require.NoError(t, tc.conn.handleTransportParameters(enabled))
	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, tc.conn.SendDatagram([]byte{0}))
	}

	started := make(chan struct{})
	errChan := make(chan error, 1)
	go func() {
		close(started)
		errChan <- tc.conn.SendDatagram([]byte("stale"))
	}()
	<-started
	select {
	case err := <-errChan:
		t.Fatalf("send returned before final transport parameters arrived: %v", err)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	require.NoError(t, tc.conn.handleTransportParameters(disabled))
	select {
	case err := <-errChan:
		require.EqualError(t, err, "datagram support disabled")
	case <-time.After(time.Second):
		t.Fatal("blocked send did not observe final transport parameters")
	}
	state := tc.conn.ConnectionState()
	require.False(t, state.SupportsDatagrams)
	require.Zero(t, state.MaxDatagramPayloadSize)
	require.Nil(t, tc.conn.datagramQueue.Peek())
}

func TestBlockedSendDatagramUsesReducedMTUBudget(t *testing.T) {
	conn := &connection{
		version:       protocol.Version1,
		datagramQueue: newDatagramQueue(func() {}, utils.DefaultLogger, 0),
	}
	conn.setCurrentMTUEstimate(1452)
	conn.setPeerTransportParameters(&wire.TransportParameters{MaxDatagramFrameSize: wire.MaxDatagramSize})
	t.Cleanup(func() { conn.datagramQueue.CloseWithError(errors.New("test cleanup")) })

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, conn.SendDatagram([]byte{0}))
	}

	errChan := make(chan error, 1)
	go func() { errChan <- conn.SendDatagram(make([]byte, 1300)) }()
	select {
	case err := <-errChan:
		t.Fatalf("send returned before MTU changed: %v", err)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	conn.setCurrentMTUEstimate(1200)
	select {
	case err := <-errChan:
		var sizeErr *DatagramTooLargeError
		require.ErrorAs(t, err, &sizeErr)
		require.Equal(t, int64(1156), sizeErr.MaxDatagramPayloadSize)
	case <-time.After(time.Second):
		t.Fatal("blocked send did not observe reduced MTU budget")
	}
}
