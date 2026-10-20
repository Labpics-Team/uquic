package quic

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/refraction-networking/uquic/internal/ackhandler"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/utils"
	"github.com/refraction-networking/uquic/internal/wire"
)

// Oracle читает настоящие сериализованные CRYPTO штатным wire parser и сравнивает
// каждый абсолютный offset. Конкатенация не скрывает пропуск или выдуманные байты.
func rcaObserveInitial(t *testing.T, packet *coalescedPacket, want, seen map[protocol.ByteCount]byte) {
	t.Helper()
	if packet == nil {
		t.Fatal("очередь CRYPTO не дала пакет")
	}
	defer packet.buffer.Release()
	if packet.buffer.Len() > 1200 {
		t.Fatalf("размер датаграммы %d превысил 1200", packet.buffer.Len())
	}
	for _, frame := range unpackInitialFrames(t, packet) {
		crypto, ok := frame.(*wire.CryptoFrame)
		if !ok {
			continue
		}
		for index, value := range crypto.Data {
			offset := crypto.Offset + protocol.ByteCount(index)
			expected, exists := want[offset]
			if !exists || value != expected {
				t.Fatalf("передан лишний/изменённый байт: offset=%d value=%d expected=%d exists=%v", offset, value, expected, exists)
			}
			seen[offset] = value
		}
	}
}

func rcaQueueRanges(queue *retransmissionQueue) string {
	var out string
	for _, frame := range queue.initialCryptoData {
		out += fmt.Sprintf("[%d,%d) ", frame.Offset, frame.Offset+protocol.ByteCount(len(frame.Data)))
	}
	return out
}

func TestUInitialRetransmissionRanges(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []*wire.CryptoFrame
	}{
		{"contiguous", []*wire.CryptoFrame{{Offset: 0, Data: []byte("ab")}, {Offset: 2, Data: []byte("cd")}}},
		{"contiguous_reversed", []*wire.CryptoFrame{{Offset: 2, Data: []byte("cd")}, {Offset: 0, Data: []byte("ab")}}},
		{"gap_after_selective_ack", []*wire.CryptoFrame{{Offset: 0, Data: []byte("ab")}, {Offset: 4, Data: []byte("ef")}}},
		{"gap_reversed", []*wire.CryptoFrame{{Offset: 4, Data: []byte("ef")}, {Offset: 0, Data: []byte("ab")}}},
		{"duplicate", []*wire.CryptoFrame{{Offset: 0, Data: []byte("abcd")}, {Offset: 0, Data: []byte("abcd")}}},
		{"overlap", []*wire.CryptoFrame{{Offset: 0, Data: []byte("abcd")}, {Offset: 2, Data: []byte("cdef")}}},
		{"overlap_reversed", []*wire.CryptoFrame{{Offset: 2, Data: []byte("cdef")}, {Offset: 0, Data: []byte("abcd")}}},
		{"split_before_gap", []*wire.CryptoFrame{{Offset: 3000, Data: []byte("tail")}, {Offset: 0, Data: bytes.Repeat([]byte("prefix"), 400)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, pto := range []bool{false, true} {
				t.Run(fmt.Sprintf("pto=%t", pto), func(t *testing.T) {
					tp, packer := newTestUPacketPacker(t)
					want, seen := make(map[protocol.ByteCount]byte), make(map[protocol.ByteCount]byte)
					for _, frame := range tc.frames {
						for index, value := range frame.Data {
							want[frame.Offset+protocol.ByteCount(index)] = value
						}
						copy := *frame
						tp.retransmissionQueue.InitialAckHandler().OnLost(&copy)
					}
					t.Logf("очередь до упаковки: %s", rcaQueueRanges(tp.retransmissionQueue))
					for flight := 0; tp.retransmissionQueue.HasInitialData() && flight < 8; flight++ {
						var packet *coalescedPacket
						var err error
						if pto {
							packet, err = packer.MaybePackPTOProbePacket(protocol.EncryptionInitial, 1200, time.Unix(1, 0), protocol.Version1)
						} else {
							packet, err = packer.PackCoalescedPacket(false, 1200, time.Unix(1, 0), protocol.Version1)
						}
						if err != nil {
							t.Fatalf("допустимая очередь повторов оборвала соединение: %v", err)
						}
						if packet == nil || len(packet.longHdrPackets) != 1 || packet.longHdrPackets[0].header.Type != protocol.PacketTypeInitial || packet.longHdrPackets[0].header.PacketNumber != protocol.PacketNumber(flight) {
							t.Fatal("нарушен номер или пространство Initial-пакета")
						}
						rcaObserveInitial(t, packet, want, seen)
					}
					if tp.retransmissionQueue.HasInitialData() || len(seen) != len(want) {
						t.Fatalf("CRYPTO потеряны или не отправлены: seen=%d want=%d queue=%s", len(seen), len(want), rcaQueueRanges(tp.retransmissionQueue))
					}
				})
			}
		})
	}
}

// Настоящий ackhandler строит очередь без прямой подстановки offsets:
// два Initial -> PTO первого -> Retry -> повтор всего неподтверждённого.
// Socket и шифрование заменены штатным unit harness; выбор CRYPTO, потеря,
// packet history, Retry и сериализация выполняются исходным кодом библиотеки.
func TestUInitialRetryAfterPTOReordersFrames(t *testing.T) {
	for _, probeBeforeRetry := range []bool{false, true} {
		t.Run(fmt.Sprintf("pto_before_retry=%t", probeBeforeRetry), func(t *testing.T) {
			tp, packer := newTestUPacketPacker(t)
			sent, _ := ackhandler.NewUAckHandler(0, 1200, &utils.RTTStats{}, true, false, protocol.PerspectiveClient, nil, utils.DefaultLogger)
			packer.pnManager = sent
			now := time.Unix(1, 0)
			register := func(packet *coalescedPacket) {
				t.Helper()
				if packet == nil {
					t.Fatal("пустой Initial")
				}
				for _, part := range packet.longHdrPackets {
					sent.SentPacket(now, part.header.PacketNumber, protocol.InvalidPacketNumber, part.streamFrames, part.frames, protocol.EncryptionInitial, protocol.ECNNon, part.length, false, false)
				}
				now = now.Add(time.Millisecond)
			}
			original := make([]byte, 1500)
			want, seen := make(map[protocol.ByteCount]byte), make(map[protocol.ByteCount]byte)
			for index := range original {
				original[index] = byte(index % 251)
				want[protocol.ByteCount(index)] = original[index]
			}
			if _, err := tp.initialStream.Write(original); err != nil {
				t.Fatal(err)
			}
			initialPackets := 0
			for tp.initialStream.HasData() && initialPackets < 8 {
				packet, err := packer.PackCoalescedPacket(false, 1200, now, protocol.Version1)
				if err != nil {
					t.Fatalf("первый flight: %v", err)
				}
				register(packet)
				packet.buffer.Release()
				initialPackets++
			}
			if initialPackets != 2 || tp.initialStream.HasData() {
				t.Fatalf("предусловие двух Initial: packets=%d remaining=%v", initialPackets, tp.initialStream.HasData())
			}
			if probeBeforeRetry {
				now = sent.GetLossDetectionTimeout()
				if err := sent.OnLossDetectionTimeout(now); err != nil {
					t.Fatal(err)
				}
				if !sent.QueueProbePacket(protocol.EncryptionInitial) {
					t.Fatal("PTO не нашёл первый Initial")
				}
				packet, err := packer.MaybePackPTOProbePacket(protocol.EncryptionInitial, 1200, now, protocol.Version1)
				if err != nil {
					t.Fatalf("PTO до Retry: %v", err)
				}
				register(packet)
				packet.buffer.Release()
			}
			sent.ResetForRetry(now)
			packer.SetToken(make([]byte, 128))
			t.Logf("реальная очередь после Retry: %s", rcaQueueRanges(tp.retransmissionQueue))
			retryPackets := 0
			for tp.retransmissionQueue.HasInitialData() && retryPackets < 8 {
				packet, err := packer.PackCoalescedPacket(false, 1200, now, protocol.Version1)
				if err != nil {
					t.Fatalf("повтор после Retry оборвал соединение: %v; queue=%s", err, rcaQueueRanges(tp.retransmissionQueue))
				}
				register(packet)
				rcaObserveInitial(t, packet, want, seen)
				retryPackets++
			}
			if tp.retransmissionQueue.HasInitialData() || len(seen) != len(want) {
				t.Fatalf("после Retry CRYPTO потеряны: seen=%d want=%d queue=%s", len(seen), len(want), rcaQueueRanges(tp.retransmissionQueue))
			}
			// В этой фикстуре 1500 байт помещаются в два Initial и с токеном 128 байт.
			if retryPackets != initialPackets {
				t.Fatalf("повтор после Retry занял %d Initial-пакетов вместо %d", retryPackets, initialPackets)
			}
		})
	}
}

// До принятия раскладки очередь остаётся исходной, включая порядок и ссылки:
// последующая попытка не должна зависеть от неудачного частичного выбора.
func TestUInitialRetransmissionRangesBudgetFailureKeepsQueue(t *testing.T) {
	for _, pto := range []bool{false, true} {
		t.Run(fmt.Sprintf("pto=%t", pto), func(t *testing.T) {
			tp, packer := newTestUPacketPacker(t)
			original := []*wire.CryptoFrame{{Offset: 3000, Data: []byte("tail")}, {Offset: 0, Data: bytes.Repeat([]byte("prefix"), 400)}}
			for _, frame := range original {
				tp.retransmissionQueue.InitialAckHandler().OnLost(frame)
			}
			before := rcaQueueRanges(tp.retransmissionQueue)
			packer.uSpec.InitialPacketSpec.FrameBuilder = QUICFrames{QUICFrameCrypto{}, QUICFramePadding{Length: 1500}}
			var packet *coalescedPacket
			var err error
			if pto {
				packet, err = packer.MaybePackPTOProbePacket(protocol.EncryptionInitial, 1200, time.Unix(1, 0), protocol.Version1)
			} else {
				packet, err = packer.PackCoalescedPacket(false, 1200, time.Unix(1, 0), protocol.Version1)
			}
			if packet != nil || err == nil || !strings.Contains(err.Error(), "budget") {
				t.Fatalf("ожидался отказ по бюджету: packet=%v error=%v", packet, err)
			}
			if rcaQueueRanges(tp.retransmissionQueue) != before || len(tp.retransmissionQueue.initialCryptoData) != len(original) {
				t.Fatal("неудачная раскладка изменила очередь")
			}
			for index, frame := range original {
				if tp.retransmissionQueue.initialCryptoData[index] != frame {
					t.Fatal("неудачная раскладка заменила исходный CRYPTO")
				}
			}
			if string(original[0].Data) != "tail" || !bytes.Equal(original[1].Data, bytes.Repeat([]byte("prefix"), 400)) {
				t.Fatal("неудачная раскладка изменила байты")
			}
			if number, _ := tp.pnManager.PeekPacketNumber(protocol.EncryptionInitial); number != 0 {
				t.Fatal("неудачная раскладка израсходовала номер пакета")
			}
		})
	}
}
