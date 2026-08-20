package quic

import (
	"context"
	"errors"
	"sync"

	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/utils"
	"github.com/refraction-networking/uquic/internal/utils/ringbuffer"
	"github.com/refraction-networking/uquic/internal/wire"
)

const (
	maxDatagramSendQueueLen = 32
	maxDatagramRcvQueueLen  = 128
)

type datagramQueue struct {
	sendMx                       sync.Mutex
	sendCond                     *sync.Cond
	sendQueue                    ringbuffer.RingBuffer[*wire.DatagramFrame]
	maxOutgoingDatagramFrameSize protocol.ByteCount
	outgoingDatagramVersion      protocol.Version

	rcvMx                          sync.Mutex
	rcvQueue                       [][]byte
	rcvd                           chan struct{} // used to notify Receive that a new datagram was received
	maxIncomingDatagramPayloadSize int64

	closeErr error
	closed   chan struct{}

	hasData func()

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger, maxIncomingDatagramPayloadSize int64) *datagramQueue {
	queue := &datagramQueue{
		hasData:                        hasData,
		rcvd:                           make(chan struct{}, 1),
		closed:                         make(chan struct{}),
		logger:                         logger,
		maxIncomingDatagramPayloadSize: maxIncomingDatagramPayloadSize,
	}
	queue.sendCond = sync.NewCond(&queue.sendMx)
	return queue
}

// Add queues a new DATAGRAM frame for sending.
// Up to 32 DATAGRAM frames will be queued.
// Once that limit is reached, Add blocks until the queue size has reduced.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()

	for {
		select {
		case <-h.closed:
			err := h.closeErr
			h.sendMx.Unlock()
			return err
		default:
		}
		if err := h.validateOutgoingDatagramFrame(f); err != nil {
			h.sendMx.Unlock()
			return err
		}
		if h.sendQueue.Len() < maxDatagramSendQueueLen {
			h.sendQueue.PushBack(f)
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		h.sendCond.Wait()
	}
}

// SetMaxOutgoingDatagramFrameSize atomically replaces the peer's DATAGRAM
// policy for queued and concurrently blocked sends.
func (h *datagramQueue) SetMaxOutgoingDatagramFrameSize(maxSize protocol.ByteCount, version protocol.Version) {
	h.sendMx.Lock()
	h.maxOutgoingDatagramFrameSize = maxSize
	h.outgoingDatagramVersion = version

	queued := h.sendQueue.Len()
	dropped := 0
	for i := 0; i < queued; i++ {
		f := h.sendQueue.PopFront()
		if h.validateOutgoingDatagramFrame(f) == nil {
			h.sendQueue.PushBack(f)
			continue
		}
		dropped++
	}
	if dropped > 0 && h.logger.Debug() {
		h.logger.Debugf("Discarding %d queued DATAGRAM frames after outgoing limit changed to %d", dropped, maxSize)
	}
	h.sendCond.Broadcast()
	h.sendMx.Unlock()
}

func (h *datagramQueue) validateOutgoingDatagramFrame(f *wire.DatagramFrame) error {
	if h.maxOutgoingDatagramFrameSize < minLengthBearingDatagramFrameSize {
		return errors.New("datagram support disabled")
	}
	if f.Length(h.outgoingDatagramVersion) <= h.maxOutgoingDatagramFrameSize {
		return nil
	}
	maxPayloadSize := (&wire.DatagramFrame{DataLenPresent: f.DataLenPresent}).MaxDataLen(
		h.maxOutgoingDatagramFrameSize,
		h.outgoingDatagramVersion,
	)
	return &DatagramTooLargeError{MaxDatagramPayloadSize: int64(maxPayloadSize)}
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if h.sendQueue.Empty() {
		return nil
	}
	return h.sendQueue.PeekFront()
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	_ = h.sendQueue.PopFront()
	h.sendCond.Signal()
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	payloadLen := int64(len(f.Data))
	maxPayloadSize := h.maxIncomingDatagramPayloadSize
	if maxPayloadSize > 0 && payloadLen > maxPayloadSize {
		if h.logger.Debug() {
			h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload, maximum %d)", payloadLen, maxPayloadSize)
		}
		return
	}

	data := make([]byte, len(f.Data))
	copy(data, f.Data)
	var queued bool
	h.rcvMx.Lock()
	if len(h.rcvQueue) < maxDatagramRcvQueueLen {
		h.rcvQueue = append(h.rcvQueue, data)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()
	if !queued && h.logger.Debug() {
		h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		h.rcvMx.Lock()
		if len(h.rcvQueue) > 0 {
			data := h.rcvQueue[0]
			h.rcvQueue = h.rcvQueue[1:]
			h.rcvMx.Unlock()
			return data, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.sendMx.Lock()
	h.closeErr = e
	close(h.closed)
	h.sendCond.Broadcast()
	h.sendMx.Unlock()
}
