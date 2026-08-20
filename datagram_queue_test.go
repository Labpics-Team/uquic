package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/utils"
	"github.com/refraction-networking/uquic/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestDatagramQueuePeekAndPop(t *testing.T) {
	var queued []struct{}
	queue := newDatagramQueue(func() { queued = append(queued, struct{}{}) }, utils.DefaultLogger, 0)
	queue.SetMaxOutgoingDatagramFrameSize(wire.MaxDatagramSize, protocol.Version1)
	require.Nil(t, queue.Peek())
	require.Empty(t, queued)
	require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("foo")}))
	require.Len(t, queued, 1)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	// calling peek again returns the same datagram
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	queue.Pop()
	require.Nil(t, queue.Peek())
}

func TestDatagramQueueSendQueueLength(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, 0)
	queue.SetMaxOutgoingDatagramFrameSize(wire.MaxDatagramSize, protocol.Version1)

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
	}
	errChan := make(chan error, 1)
	go func() { errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()

	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// peeking doesn't remove the datagram from the queue...
	require.NotNil(t, queue.Peek())
	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// ...but popping does
	queue.Pop()
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	// pop all the remaining datagrams
	for i := 1; i < maxDatagramSendQueueLen; i++ {
		queue.Pop()
	}
	f := queue.Peek()
	require.NotNil(t, f)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foobar")}, f)
}

func TestDatagramQueueRejectsFrameAfterOutgoingLimitIsRevoked(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, 0)
	queue.SetMaxOutgoingDatagramFrameSize(wire.MaxDatagramSize, protocol.Version1)
	queue.SetMaxOutgoingDatagramFrameSize(1, protocol.Version1)

	err := queue.Add(&wire.DatagramFrame{DataLenPresent: true})
	require.EqualError(t, err, "datagram support disabled")
	require.Nil(t, queue.Peek())
}

func TestDatagramQueuePurgesOnlyFramesInvalidatedByReducedOutgoingLimit(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, 0)
	queue.SetMaxOutgoingDatagramFrameSize(wire.MaxDatagramSize, protocol.Version1)
	require.NoError(t, queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: []byte("a")}))
	require.NoError(t, queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: []byte("four")}))
	require.NoError(t, queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: []byte("b")}))

	queue.SetMaxOutgoingDatagramFrameSize(3, protocol.Version1)
	require.Equal(t, []byte("a"), queue.Peek().Data)
	queue.Pop()
	require.Equal(t, []byte("b"), queue.Peek().Data)
	queue.Pop()
	require.Nil(t, queue.Peek())
}

func TestDatagramQueueWakesBlockedSendWhenOutgoingLimitIsRevoked(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, 0)
	queue.SetMaxOutgoingDatagramFrameSize(wire.MaxDatagramSize, protocol.Version1)
	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: []byte{0}}))
	}

	const blockedSends = 3
	started := make(chan struct{}, blockedSends)
	errChan := make(chan error, blockedSends)
	for i := 0; i < blockedSends; i++ {
		go func() {
			started <- struct{}{}
			errChan <- queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: []byte("stale")})
		}()
	}
	for i := 0; i < blockedSends; i++ {
		<-started
	}
	select {
	case err := <-errChan:
		t.Fatalf("send returned before queue policy changed: %v", err)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	queue.SetMaxOutgoingDatagramFrameSize(1, protocol.Version1)
	for i := 0; i < blockedSends; i++ {
		select {
		case err := <-errChan:
			require.EqualError(t, err, "datagram support disabled")
		case <-time.After(time.Second):
			t.Fatal("blocked send was not woken by outgoing policy change")
		}
	}
	require.Nil(t, queue.Peek())
}

func TestDatagramQueueRevalidatesBlockedSendAfterOutgoingLimitReduction(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, 0)
	queue.SetMaxOutgoingDatagramFrameSize(wire.MaxDatagramSize, protocol.Version1)
	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: []byte{0}}))
	}

	errChan := make(chan error, 1)
	go func() { errChan <- queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: []byte("stale")}) }()
	select {
	case err := <-errChan:
		t.Fatalf("send returned before queue policy changed: %v", err)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	queue.SetMaxOutgoingDatagramFrameSize(3, protocol.Version1)
	select {
	case err := <-errChan:
		var sizeErr *DatagramTooLargeError
		require.ErrorAs(t, err, &sizeErr)
		require.Equal(t, int64(1), sizeErr.MaxDatagramPayloadSize)
	case <-time.After(time.Second):
		t.Fatal("blocked send was not revalidated after outgoing policy change")
	}
}

func TestDatagramQueueKeepsBlockedSendAfterOutgoingLimitIncrease(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, 0)
	queue.SetMaxOutgoingDatagramFrameSize(10, protocol.Version1)
	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: []byte{0}}))
	}

	started := make(chan struct{})
	errChan := make(chan error, 1)
	go func() {
		close(started)
		errChan <- queue.Add(&wire.DatagramFrame{DataLenPresent: true, Data: []byte("fresh")})
	}()
	<-started

	queue.SetMaxOutgoingDatagramFrameSize(wire.MaxDatagramSize, protocol.Version1)
	select {
	case err := <-errChan:
		t.Fatalf("send returned while the full queue still had no space: %v", err)
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	queue.Pop()
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("blocked send did not resume after queue space became available")
	}
}

func TestDatagramQueueReceive(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, 0)

	// receive frames that were received earlier
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foo")})
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("bar")})
	data, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), data)
	data, err = queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)
}

func TestDatagramQueueDropsOversizedReceiveWithoutBufferingPayload(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, 3)
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("four")})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data, err := queue.Receive(ctx)
	require.Nil(t, data)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, queue.rcvQueue)

	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("ok")})
	data, err = queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("ok"), data)
}

func TestDatagramQueueReceiveBlocking(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, 0)

	// block until a new frame is received
	type result struct {
		data []byte
		err  error
	}
	resultChan := make(chan result, 1)
	go func() {
		data, err := queue.Receive(context.Background())
		resultChan <- result{data, err}
	}()

	select {
	case <-resultChan:
		t.Fatal("expected to not receive result")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
	select {
	case result := <-resultChan:
		require.NoError(t, result.err)
		require.Equal(t, []byte("foobar"), result.data)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// unblock when the context is canceled
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() {
		_, err := queue.Receive(ctx)
		errChan <- err
	}()
	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	cancel()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestDatagramQueueClose(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger, 0)
	queue.SetMaxOutgoingDatagramFrameSize(wire.MaxDatagramSize, protocol.Version1)

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
	}
	errChan1 := make(chan error, 1)
	go func() { errChan1 <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()
	errChan2 := make(chan error, 1)
	go func() {
		_, err := queue.Receive(context.Background())
		errChan2 <- err
	}()

	queue.CloseWithError(errors.New("test error"))

	select {
	case err := <-errChan1:
		require.EqualError(t, err, "test error")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	select {
	case err := <-errChan2:
		require.EqualError(t, err, "test error")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}
