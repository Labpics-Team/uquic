package quic

import (
	"bytes"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/refraction-networking/clienthellod"
	"github.com/refraction-networking/uquic/internal/handshake"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func newTestUPacketPacker(t *testing.T, configure ...func(*testPacketPacker, *gomock.Controller)) (*testPacketPacker, *uPacketPacker) {
	t.Helper()
	ctrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
	for _, setup := range configure {
		setup(tp, ctrl)
	}
	sealer := newMockShortHeaderSealerWithOverhead(ctrl, 16)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(sealer, nil).AnyTimes()
	tp.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
	tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
	tp.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	var number protocol.PacketNumber
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).DoAndReturn(func(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
		return number, protocol.PacketNumberLen2
	}).AnyTimes()
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).DoAndReturn(func(protocol.EncryptionLevel) protocol.PacketNumber {
		result := number
		number++
		return result
	}).AnyTimes()
	spec, err := QUICID2Spec(CurrentChromeParrot())
	require.NoError(t, err)
	return tp, newUPacketPacker(tp.packer, &spec)
}

func initialFrames(t *testing.T, packet *coalescedPacket) (*wire.ExtendedHeader, []clienthellod.QUICFrame) {
	t.Helper()
	header, data, _, err := wire.ParsePacket(packet.buffer.Data)
	require.NoError(t, err)
	extended, err := header.ParseExtended(data)
	require.NoError(t, err)
	frames, err := readQUICFrames(data[extended.GetLength(protocol.Version1) : len(data)-16])
	require.NoError(t, err)
	return extended, frames
}

// Размер проверяется по сериализованной датаграмме, данные — независимым parser.
// Все фрагменты ClientHello должны дойти, а номер пакета расходуется ровно один раз.
func TestUInitialFlightFitsDatagramBudget(t *testing.T) {
	for _, budget := range []protocol.ByteCount{1200, 1280, 1452} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			tp, packer := newTestUPacketPacker(t)
			builder := packer.uSpec.InitialPacketSpec.FrameBuilder.(*QUICRandomFrames)
			originalBuilder := *builder
			original := bytes.Repeat([]byte("client hello"), 250)
			_, err := tp.initialStream.Write(original)
			require.NoError(t, err)
			var received []byte
			var number protocol.PacketNumber
			for tp.initialStream.HasData() {
				packet, err := packer.PackCoalescedPacket(false, budget, time.Now(), protocol.Version1)
				require.NoError(t, err)
				require.NotNil(t, packet)
				require.LessOrEqual(t, packet.buffer.Len(), budget, "Initial превысил UDP-бюджет после раскладки CRYPTO")
				header, frames := initialFrames(t, packet)
				require.Equal(t, number, header.PacketNumber)
				part, err := clienthellod.ReassembleCRYPTOFrames(frames)
				require.NoError(t, err)
				require.Equal(t, uint64(len(received)), cryptoBaseOffset(frames))
				require.NotEmpty(t, part)
				received = append(received, part...)
				number++
				packet.buffer.Release()
			}
			require.Equal(t, original, received)
			require.Equal(t, originalBuilder, *builder, "MTU одного соединения не должен менять общий профиль")
		})
	}
}

func TestUInitialLawfulProfileFitsDatagramBudget(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		cryptoMin, cryptoMax uint8
		tokenLen, dataLen    int
	}{
		{name: "neighbor_control", cryptoMin: 2, cryptoMax: 3, dataLen: 70},
		{name: "many_short_crypto", cryptoMin: 70, cryptoMax: 71, dataLen: 70},
		{name: "long_token_small_crypto", cryptoMin: 2, cryptoMax: 8, tokenLen: 1020, dataLen: 8},
		{name: "maximum_short_crypto", cryptoMin: 254, cryptoMax: 255, dataLen: 1},
		{name: "maximum_crypto_crosses_varint", cryptoMin: 254, cryptoMax: 255, dataLen: 70},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tp, packer := newTestUPacketPacker(t)
			packer.uSpec.InitialPacketSpec.FrameBuilder = &QUICRandomFrames{
				MinCRYPTO: tc.cryptoMin,
				MaxCRYPTO: tc.cryptoMax,
			}
			packer.SetToken(bytes.Repeat([]byte{17}, tc.tokenLen))
			original := bytes.Repeat([]byte{42}, tc.dataLen)
			_, err := tp.initialStream.Write(original)
			require.NoError(t, err)
			packet, err := packer.PackCoalescedPacket(false, 1200, time.Now(), protocol.Version1)
			require.NoError(t, err)
			require.NotNil(t, packet)
			defer packet.buffer.Release()
			require.Equal(t, protocol.ByteCount(1200), packet.buffer.Len())
			header, frames := initialFrames(t, packet)
			require.Zero(t, header.PacketNumber)
			reassembled, err := clienthellod.ReassembleCRYPTOFrames(frames)
			require.NoError(t, err)
			require.Equal(t, original, reassembled)
			require.False(t, tp.initialStream.HasData())
			require.False(t, tp.retransmissionQueue.HasInitialData())
			var cryptoCount int
			for _, frame := range frames {
				if _, ok := frame.(*clienthellod.CRYPTO); ok {
					cryptoCount++
				}
			}
			require.GreaterOrEqual(t, cryptoCount, int(tc.cryptoMin))
			require.Less(t, cryptoCount, int(tc.cryptoMax))
		})
	}
}

// Повтор CRYPTO в PTO обязан соблюдать тот же предел и сохранять абсолютный offset.
func TestUInitialPTOFitsDatagramBudget(t *testing.T) {
	tp, packer := newTestUPacketPacker(t)
	original := bytes.Repeat([]byte{42}, 3000)
	tp.retransmissionQueue.addInitial(&wire.CryptoFrame{Offset: 16380, Data: original})
	var received []byte
	var number protocol.PacketNumber
	for tp.retransmissionQueue.HasInitialData() {
		packet, err := packer.MaybePackPTOProbePacket(protocol.EncryptionInitial, 1280, time.Now(), protocol.Version1)
		require.NoError(t, err)
		require.NotNil(t, packet)
		require.LessOrEqual(t, packet.buffer.Len(), protocol.ByteCount(1280))
		header, frames := initialFrames(t, packet)
		require.Equal(t, number, header.PacketNumber)
		part, err := clienthellod.ReassembleCRYPTOFrames(frames)
		require.NoError(t, err)
		require.Equal(t, uint64(16380+len(received)), cryptoBaseOffset(frames))
		require.NotEmpty(t, part)
		received = append(received, part...)
		number++
		packet.buffer.Release()
	}
	require.Equal(t, original, received)
}

func TestUInitialSentFramesReturnToLiveRetransmissionQueue(t *testing.T) {
	tp, packer := newTestUPacketPacker(t)
	original := bytes.Repeat([]byte{42}, 1500)
	_, err := tp.initialStream.Write(original)
	require.NoError(t, err)
	packet, err := packer.PackCoalescedPacket(false, 1200, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, packet)
	_, frames := initialFrames(t, packet)
	sent, err := clienthellod.ReassembleCRYPTOFrames(frames)
	require.NoError(t, err)
	require.NotEmpty(t, sent)
	require.Equal(t, original, append(append([]byte(nil), sent...), tp.initialStream.writeBuf...))
	for _, frame := range packet.longHdrPackets[0].frames {
		frame.Handler.OnLost(frame.Frame)
	}
	packet.buffer.Release()
	require.True(t, tp.retransmissionQueue.HasInitialData())
	var received []byte
	for tp.retransmissionQueue.HasInitialData() {
		packet, err = packer.MaybePackPTOProbePacket(protocol.EncryptionInitial, 1200, time.Now(), protocol.Version1)
		require.NoError(t, err)
		require.NotNil(t, packet)
		require.LessOrEqual(t, packet.buffer.Len(), protocol.ByteCount(1200))
		_, frames = initialFrames(t, packet)
		require.Equal(t, uint64(len(received)), cryptoBaseOffset(frames))
		part, err := clienthellod.ReassembleCRYPTOFrames(frames)
		require.NoError(t, err)
		require.NotEmpty(t, part)
		received = append(received, part...)
		packet.buffer.Release()
	}
	require.Equal(t, sent, received)
	require.Equal(t, original, append(received, tp.initialStream.writeBuf...))
}

func TestUInitialRetransmissionBudgetErrorKeepsQueue(t *testing.T) {
	tp, packer := newTestUPacketPacker(t)
	original := bytes.Repeat([]byte{42}, 3000)
	frame := &wire.CryptoFrame{Offset: 16380, Data: original}
	tp.retransmissionQueue.addInitial(frame)
	tp.retransmissionQueue.AddPing(protocol.EncryptionInitial)
	packer.uSpec.InitialPacketSpec.FrameBuilder = QUICFrames{QUICFrameCrypto{}, QUICFramePadding{Length: 1500}}
	packet, err := packer.MaybePackPTOProbePacket(protocol.EncryptionInitial, 1200, time.Now(), protocol.Version1)
	require.ErrorContains(t, err, "budget")
	require.Nil(t, packet)
	require.Equal(t, protocol.ByteCount(16380), frame.Offset)
	require.Equal(t, original, frame.Data)
	require.Equal(t, []*wire.CryptoFrame{frame}, tp.retransmissionQueue.initialCryptoData)
	require.Len(t, tp.retransmissionQueue.initial, 1)
	require.IsType(t, &wire.PingFrame{}, tp.retransmissionQueue.initial[0])
	pn, _ := tp.pnManager.PeekPacketNumber(protocol.EncryptionInitial)
	require.Zero(t, pn)
}

func unpackInitialFrames(t *testing.T, packet *coalescedPacket) []wire.Frame {
	t.Helper()
	header, data, _, err := wire.ParsePacket(packet.buffer.Data)
	require.NoError(t, err)
	extended, err := header.ParseExtended(data)
	require.NoError(t, err)
	data = data[extended.GetLength(protocol.Version1) : len(data)-16]
	parser := wire.NewFrameParser(false)
	var frames []wire.Frame
	for len(data) > 0 {
		n, frame, err := parser.ParseNext(data, protocol.EncryptionInitial, protocol.Version1)
		require.NoError(t, err)
		require.Positive(t, n)
		data = data[n:]
		if frame != nil {
			frames = append(frames, frame)
		}
	}
	return frames
}

func TestUInitialPreservesACKAndPTOControlFrames(t *testing.T) {
	for _, withCrypto := range []bool{false, true} {
		t.Run(fmt.Sprint(withCrypto), func(t *testing.T) {
			ack := &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 7}}}
			tp, packer := newTestUPacketPacker(t, func(tp *testPacketPacker, _ *gomock.Controller) {
				tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false).Return(ack)
			})
			// Убираем декоративные PING, чтобы проверить именно очередь повторов.
			frames := packer.uSpec.InitialPacketSpec.FrameBuilder.(*QUICRandomFrames)
			frames.MinPING, frames.MaxPING = 0, 0
			tp.retransmissionQueue.AddPing(protocol.EncryptionInitial)
			if withCrypto {
				tp.retransmissionQueue.addInitial(&wire.CryptoFrame{Offset: 64, Data: []byte("crypto")})
			}
			packet, err := packer.MaybePackPTOProbePacket(protocol.EncryptionInitial, 1280, time.Now(), protocol.Version1)
			require.NoError(t, err)
			require.NotNil(t, packet)
			defer packet.buffer.Release()
			require.LessOrEqual(t, packet.buffer.Len(), protocol.ByteCount(1280))
			var ackCount, pingCount int
			for _, frame := range unpackInitialFrames(t, packet) {
				switch f := frame.(type) {
				case *wire.AckFrame:
					require.Equal(t, ack.AckRanges, f.AckRanges)
					ackCount++
				case *wire.PingFrame:
					pingCount++
				}
			}
			require.Equal(t, 1, ackCount)
			require.Equal(t, 1, pingCount)
		})
	}
}

func TestUInitialPTOOnlyPing(t *testing.T) {
	tp, packer := newTestUPacketPacker(t)
	tp.retransmissionQueue.AddPing(protocol.EncryptionInitial)
	var packet *coalescedPacket
	require.NotPanics(t, func() {
		var err error
		packet, err = packer.MaybePackPTOProbePacket(protocol.EncryptionInitial, 1280, time.Now(), protocol.Version1)
		require.NoError(t, err)
	})
	require.NotNil(t, packet)
	defer packet.buffer.Release()
	require.Equal(t, protocol.ByteCount(1200), packet.buffer.Len())
	frames := unpackInitialFrames(t, packet)
	require.Len(t, frames, 1)
	require.IsType(t, &wire.PingFrame{}, frames[0])
}

func TestUInitialCoalescedShortHeaderHasNoExternalPadding(t *testing.T) {
	tp, packer := newTestUPacketPacker(t, func(tp *testPacketPacker, ctrl *gomock.Controller) {
		tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealerWithOverhead(ctrl, 16), nil).AnyTimes()
		tp.pnManager.EXPECT().PeekPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(12), protocol.PacketNumberLen2)
		tp.pnManager.EXPECT().PopPacketNumber(protocol.Encryption1RTT).Return(protocol.PacketNumber(12))
		tp.framer.EXPECT().HasData().Return(false)
	})
	packer.uSpec.InitialPacketSpec.FrameBuilder.(*QUICRandomFrames).Length = 0
	_, err := tp.initialStream.Write([]byte("initial"))
	require.NoError(t, err)
	tp.retransmissionQueue.AddPing(protocol.Encryption1RTT)
	packet, err := packer.PackCoalescedPacket(false, 1280, time.Now(), protocol.Version1)
	require.NoError(t, err)
	require.NotNil(t, packet)
	defer packet.buffer.Release()
	require.NotNil(t, packet.shortHdrPacket)
	require.Equal(t, protocol.ByteCount(1200), packet.buffer.Len())
	_, _, remaining, err := wire.ParsePacket(packet.buffer.Data)
	require.NoError(t, err)
	require.Equal(t, int(packet.shortHdrPacket.Length), len(remaining))
	// Mock sealer оставляет 16 байт tag; внешний padding изменил бы хвост.
	require.Equal(t, bytes.Repeat([]byte{'s'}, 16), remaining[len(remaining)-16:])
	headerLength, number, _, _, err := wire.ParseShortHeader(remaining, testPackerConnIDLen)
	require.NoError(t, err)
	require.Equal(t, protocol.PacketNumber(12), number)
	_, frame, err := wire.NewFrameParser(false).ParseNext(remaining[headerLength:len(remaining)-16], protocol.Encryption1RTT, protocol.Version1)
	require.NoError(t, err)
	require.IsType(t, &wire.PingFrame{}, frame)
}

func TestUInitialCoalescedHandshakeRemainsReadable(t *testing.T) {
	for _, padding := range []uint16{0, 1215} {
		t.Run(fmt.Sprint(padding), func(t *testing.T) {
			tp, packer := newTestUPacketPacker(t, func(tp *testPacketPacker, ctrl *gomock.Controller) {
				tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealerWithOverhead(ctrl, 16), nil).AnyTimes()
				tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(12), protocol.PacketNumberLen2)
				tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionHandshake).Return(protocol.PacketNumber(12))
			})
			packer.uSpec.InitialPacketSpec.FrameBuilder.(*QUICRandomFrames).Length = padding
			_, err := tp.initialStream.Write([]byte("initial"))
			require.NoError(t, err)
			handshakeData := bytes.Repeat([]byte{17}, 100)
			_, err = tp.handshakeStream.Write(handshakeData)
			require.NoError(t, err)
			packet, err := packer.PackCoalescedPacket(false, 1452, time.Now(), protocol.Version1)
			require.NoError(t, err)
			require.NotNil(t, packet)
			defer packet.buffer.Release()
			require.GreaterOrEqual(t, packet.buffer.Len(), protocol.ByteCount(1200))
			require.LessOrEqual(t, packet.buffer.Len(), protocol.ByteCount(1452))
			require.Len(t, packet.longHdrPackets, 2)
			_, _, remaining, err := wire.ParsePacket(packet.buffer.Data)
			require.NoError(t, err)
			header, data, _, err := wire.ParsePacket(remaining)
			require.NoError(t, err, "padding не должен разрывать составную датаграмму")
			require.NotNil(t, header)
			require.Equal(t, protocol.PacketTypeHandshake, header.Type)
			extended, err := header.ParseExtended(data)
			require.NoError(t, err)
			require.Equal(t, protocol.PacketNumber(12), extended.PacketNumber)
			frames, err := readQUICFrames(data[extended.GetLength(protocol.Version1) : len(data)-16])
			require.NoError(t, err)
			reassembled, err := clienthellod.ReassembleCRYPTOFrames(frames)
			require.NoError(t, err)
			require.Equal(t, handshakeData, reassembled)
		})
	}
}

func TestUInitialLargeACKPreservesCRYPTO(t *testing.T) {
	for _, cryptoCount := range []uint8{2, 16} {
		t.Run(fmt.Sprint(cryptoCount), func(t *testing.T) {
			ack := &wire.AckFrame{}
			for number := protocol.PacketNumber(2000); number > 0; number -= 2 {
				ack.AckRanges = append(ack.AckRanges, wire.AckRange{Smallest: number, Largest: number})
			}
			tp, packer := newTestUPacketPacker(t, func(tp *testPacketPacker, _ *gomock.Controller) {
				tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false).Return(ack)
			})
			packer.uSpec.InitialPacketSpec.FrameBuilder = &QUICRandomFrames{MinCRYPTO: cryptoCount, MaxCRYPTO: cryptoCount}
			packer.SetToken(bytes.Repeat([]byte{1}, 128))
			original := bytes.Repeat([]byte{23}, 100)
			_, err := tp.initialStream.Write(original)
			require.NoError(t, err)
			packet, err := packer.PackCoalescedPacket(false, 1200, time.Now(), protocol.Version1)
			require.NoError(t, err)
			require.NotNil(t, packet)
			require.LessOrEqual(t, packet.buffer.Len(), protocol.ByteCount(1200))
			frames := unpackInitialFrames(t, packet)
			require.IsType(t, &wire.AckFrame{}, frames[0])
			var received []byte
			if cryptoCount == 16 {
				// Одного байта с 16 заголовками здесь недостаточно для прогресса.
				require.Len(t, frames, 1)
			} else {
				// clienthellod не разбирает ACK; штатный parser уже отделил
				// CRYPTO, которые собираем в порядке абсолютных offsets.
				var cryptoFrames []*wire.CryptoFrame
				for _, frame := range frames {
					if crypto, ok := frame.(*wire.CryptoFrame); ok {
						cryptoFrames = append(cryptoFrames, crypto)
					}
				}
				sort.Slice(cryptoFrames, func(i, j int) bool { return cryptoFrames[i].Offset < cryptoFrames[j].Offset })
				for _, crypto := range cryptoFrames {
					require.Equal(t, protocol.ByteCount(len(received)), crypto.Offset)
					received = append(received, crypto.Data...)
				}
				require.NotEmpty(t, received, "Помещающийся префикс должен уйти вместе с ACK")
			}
			packet.buffer.Release()
			require.True(t, tp.initialStream.HasData())
			require.Equal(t, original, append(append([]byte(nil), received...), tp.initialStream.writeBuf...))
			packet, err = packer.PackCoalescedPacket(false, 1200, time.Now(), protocol.Version1)
			require.NoError(t, err)
			require.NotNil(t, packet)
			defer packet.buffer.Release()
			require.LessOrEqual(t, packet.buffer.Len(), protocol.ByteCount(1200))
			header, cryptoFrames := initialFrames(t, packet)
			require.Equal(t, protocol.PacketNumber(1), header.PacketNumber)
			require.Equal(t, uint64(len(received)), cryptoBaseOffset(cryptoFrames))
			reassembled, err := clienthellod.ReassembleCRYPTOFrames(cryptoFrames)
			require.NoError(t, err)
			require.Equal(t, original, append(received, reassembled...))
			require.False(t, tp.initialStream.HasData())
		})
	}
}

func TestUInitialRejectsImpossibleProfileBudget(t *testing.T) {
	for _, minimum := range []bool{false, true} {
		t.Run(fmt.Sprint(minimum), func(t *testing.T) {
			tp, packer := newTestUPacketPacker(t)
			if minimum {
				packer.uSpec.UDPDatagramMinSize = 1357
			} else {
				packer.uSpec.InitialPacketSpec.FrameBuilder = QUICFrames{QUICFrameCrypto{}, QUICFramePadding{Length: 1500}}
			}
			_, err := tp.initialStream.Write([]byte("hello"))
			require.NoError(t, err)
			packet, err := packer.PackCoalescedPacket(false, 1280, time.Now(), protocol.Version1)
			require.ErrorContains(t, err, "budget")
			require.Nil(t, packet)
			require.Equal(t, []byte("hello"), tp.initialStream.writeBuf)
			require.Zero(t, tp.initialStream.writeOffset)
			pn, _ := tp.pnManager.PeekPacketNumber(protocol.EncryptionInitial)
			require.Zero(t, pn)
		})
	}
}
