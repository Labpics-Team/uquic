package self_test

import (
	"testing"

	quicproxy "github.com/refraction-networking/uquic/integrationtests/tools/proxy"

	"github.com/stretchr/testify/require"
)

func TestRandomDropDirectionAndBurstLimit(t *testing.T) {
	for _, scope := range []quicproxy.Direction{quicproxy.DirectionIncoming, quicproxy.DirectionOutgoing, quicproxy.DirectionBoth} {
		t.Run(scope.String(), func(t *testing.T) {
			draws := 0
			drop := dropCallbackRandom(scope, func(n int64) int64 {
				require.Equal(t, int64(3), n)
				draws++
				return 0
			})
			for packet := 1; packet <= 12; packet++ {
				for _, direction := range []quicproxy.Direction{quicproxy.DirectionIncoming, quicproxy.DirectionOutgoing} {
					want := direction.Is(scope) && packet != 11
					require.Equal(t, want, drop(direction, nil), "packet %d, direction %s", packet, direction)
				}
			}
			wantDraws := 12
			if scope == quicproxy.DirectionBoth {
				wantDraws *= 2
			}
			require.Equal(t, wantDraws, draws)
		})
	}
}

func TestRandomDropResetsBurstAfterDelivery(t *testing.T) {
	draws := 0
	drop := dropCallbackRandom(quicproxy.DirectionIncoming, func(int64) int64 {
		draws++
		if draws == 3 {
			return 1
		}
		return 0
	})
	for _, want := range []bool{true, true, false} {
		require.Equal(t, want, drop(quicproxy.DirectionIncoming, nil))
	}
	for packet := 1; packet <= 10; packet++ {
		require.True(t, drop(quicproxy.DirectionIncoming, nil), "packet %d after delivery", packet)
	}
	require.False(t, drop(quicproxy.DirectionIncoming, nil))
}
