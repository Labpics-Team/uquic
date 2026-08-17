package quic

import (
	"testing"

	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestMaxDatagramPayloadSizeTracksCurrentMTU(t *testing.T) {
	conn := &connection{
		peerParams: &wire.TransportParameters{MaxDatagramFrameSize: wire.MaxDatagramSize},
		version:    protocol.Version1,
	}
	frame := &wire.DatagramFrame{DataLenPresent: true}

	for _, mtu := range []protocol.ByteCount{1200, 1452, 1280} {
		conn.currentMTUEstimate.Store(uint32(mtu))
		want := min(
			frame.MaxDataLen(wire.MaxDatagramSize, protocol.Version1),
			estimateMaxPayloadSize(mtu),
		)
		require.Equal(t, want, conn.maxDatagramPayloadSize())
	}
}

func TestMaxDatagramPayloadSizeReturnsZeroWithoutPeerSupport(t *testing.T) {
	require.Zero(t, (&connection{}).maxDatagramPayloadSize())
}

func TestEstimateMaxDatagramPayloadSizeDoesNotUnderflow(t *testing.T) {
	require.Zero(t, estimateMaxPayloadSize(0))
	require.Zero(t, estimateMaxPayloadSize(37))
}
