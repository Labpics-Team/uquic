package quic

import (
	"fmt"
	"time"

	"github.com/refraction-networking/clienthellod"
	"github.com/refraction-networking/uquic/internal/handshake"
	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/wire"
)

// uPacketPacker is an extended packetPacker which is used
// to customize some of the packetPacker's behaviors for
// UQUIC.
type uPacketPacker struct {
	*packetPacker

	// initPktNbrLen      PacketNumberLen
	// qfs                QUICFrames // [UQUIC] uses QUICFrames to customize encrypted frames
	// udpDatagramMinSize int
	uSpec *QUICSpec // [UQUIC]
}

func newUPacketPacker(
	packetPacker *packetPacker,
	uSpec *QUICSpec, // [UQUIC]
) *uPacketPacker {
	return &uPacketPacker{
		packetPacker: packetPacker,
		uSpec:        uSpec, // [UQUIC]
	}
}

// PackCoalescedPacket packs a new packet.
// It packs an Initial / Handshake if there is data to send in these packet number spaces.
// It should only be called before the handshake is confirmed.
func (p *uPacketPacker) PackCoalescedPacket(onlyAck bool, maxSize protocol.ByteCount, now time.Time, v protocol.Version) (*coalescedPacket, error) {
	var (
		initialHdr, handshakeHdr, zeroRTTHdr                            *wire.ExtendedHeader
		initialPayload, handshakePayload, zeroRTTPayload, oneRTTPayload payload
		oneRTTPacketNumber                                              protocol.PacketNumber
		oneRTTPacketNumberLen                                           protocol.PacketNumberLen
		initialData                                                     []byte
	)
	// Try packing an Initial packet.
	initialSealer, err := p.cryptoSetup.GetInitialSealer()
	if err != nil && err != handshake.ErrKeysDropped {
		return nil, err
	}
	var size protocol.ByteCount
	if initialSealer != nil {
		initialHdr, initialPayload, initialData, err = p.prepareInitialPacket(maxSize, initialSealer.Overhead(), now, onlyAck, v)
		if err != nil {
			return nil, err
		}
		if initialPayload.length > 0 {
			if initialData != nil {
				size = initialHdr.GetLength(v) + protocol.ByteCount(len(initialData)+initialSealer.Overhead())
			} else {
				size = p.longHeaderPacketLength(initialHdr, initialPayload, v) + protocol.ByteCount(initialSealer.Overhead())
			}
		}

		// // [UQUIC]
		// if len(initialPayload.frames) > 0 {
		// 	fmt.Printf("onlyAck: %t, PackCoalescedPacket: %v\n", onlyAck, initialPayload.frames[0].Frame)
		// }
	}

	// Add a Handshake packet.
	var handshakeSealer sealer
	if (onlyAck && size == 0) || (!onlyAck && size < maxSize-protocol.MinCoalescedPacketSize) {
		var err error
		handshakeSealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if handshakeSealer != nil {
			handshakeHdr, handshakePayload = p.maybeGetCryptoPacket(
				maxSize-size-protocol.ByteCount(handshakeSealer.Overhead()),
				protocol.EncryptionHandshake,
				now,
				onlyAck,
				size == 0,
				v,
			)
			if handshakePayload.length > 0 {
				s := p.longHeaderPacketLength(handshakeHdr, handshakePayload, v) + protocol.ByteCount(handshakeSealer.Overhead())
				size += s
			}
		}
	}

	// Add a 0-RTT / 1-RTT packet.
	var zeroRTTSealer sealer
	var oneRTTSealer handshake.ShortHeaderSealer
	var connID protocol.ConnectionID
	var kp protocol.KeyPhaseBit
	if (onlyAck && size == 0) || (!onlyAck && size < maxSize-protocol.MinCoalescedPacketSize) {
		var err error
		oneRTTSealer, err = p.cryptoSetup.Get1RTTSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if err == nil { // 1-RTT
			kp = oneRTTSealer.KeyPhase()
			connID = p.getDestConnID()
			oneRTTPacketNumber, oneRTTPacketNumberLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
			hdrLen := wire.ShortHeaderLen(connID, oneRTTPacketNumberLen)
			oneRTTPayload = p.maybeGetShortHeaderPacket(oneRTTSealer, hdrLen, maxSize-size, onlyAck, size == 0, now, v)
			if oneRTTPayload.length > 0 {
				size += p.shortHeaderPacketLength(connID, oneRTTPacketNumberLen, oneRTTPayload) + protocol.ByteCount(oneRTTSealer.Overhead())
			}
		} else if p.perspective == protocol.PerspectiveClient && !onlyAck { // 0-RTT packets can't contain ACK frames
			var err error
			zeroRTTSealer, err = p.cryptoSetup.Get0RTTSealer()
			if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
				return nil, err
			}
			if zeroRTTSealer != nil {
				zeroRTTHdr, zeroRTTPayload = p.maybeGetAppDataPacketFor0RTT(zeroRTTSealer, maxSize-size, now, v)
				if zeroRTTPayload.length > 0 {
					size += p.longHeaderPacketLength(zeroRTTHdr, zeroRTTPayload, v) + protocol.ByteCount(zeroRTTSealer.Overhead())
				}
			}
		}
	}

	if initialPayload.length == 0 && handshakePayload.length == 0 && zeroRTTPayload.length == 0 && oneRTTPayload.length == 0 {
		return nil, nil
	}

	buffer := getPacketBuffer()
	packet := &coalescedPacket{
		buffer:         buffer,
		longHdrPackets: make([]*longHeaderPacket, 0, 3),
	}
	if initialPayload.length > 0 {
		if onlyAck || len(initialPayload.frames) == 0 {
			// TODO: uQUIC should send Initial Packet ACK if requested.
			// However, it should be otherwise configurable whether to request
			// to send Initial Packet ACK or not. See quic-go#4007
			padding := p.initialPaddingLen(initialPayload.frames, size, maxSize)
			cont, err := p.appendLongHeaderPacket(buffer, initialHdr, initialPayload, padding, protocol.EncryptionInitial, initialSealer, v)
			if err != nil {
				return nil, err
			}
			packet.longHdrPackets = append(packet.longHdrPackets, cont)
		} else { // [UQUIC]
			cont, err := p.appendInitialPacket(buffer, initialHdr, initialPayload, initialData, protocol.EncryptionInitial, initialSealer, v)
			if err != nil {
				return nil, err
			}

			packet.longHdrPackets = append(packet.longHdrPackets, cont)
		}
	}
	if handshakePayload.length > 0 {
		cont, err := p.appendLongHeaderPacket(buffer, handshakeHdr, handshakePayload, 0, protocol.EncryptionHandshake, handshakeSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if zeroRTTPayload.length > 0 {
		longHdrPacket, err := p.appendLongHeaderPacket(buffer, zeroRTTHdr, zeroRTTPayload, 0, protocol.Encryption0RTT, zeroRTTSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
	} else if oneRTTPayload.length > 0 {
		var padding protocol.ByteCount
		if initialData != nil {
			// Короткий заголовок занимает остаток датаграммы: padding должен
			// войти в шифруемый пакет, иначе изменится его authentication tag.
			padding = max(0, p.initialDatagramMinSize()-size)
		}
		shp, err := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, kp, oneRTTPayload, padding, maxSize, oneRTTSealer, false, v)
		if err != nil {
			return nil, err
		}
		packet.shortHdrPacket = &shp
	}
	if initialData != nil {
		p.padInitialDatagram(buffer)
	}
	return packet, nil
}

// prepareInitialPacket резервирует заголовки раскладки до извлечения CRYPTO из
// очереди. Окончательная раскладка выбирается один раз и участвует в общем бюджете
// до добавления Handshake/0-RTT: повторная случайная раскладка изменила бы размер.
func (p *uPacketPacker) prepareInitialPacket(maxSize protocol.ByteCount, overhead int, now time.Time, onlyAck bool, v protocol.Version) (*wire.ExtendedHeader, payload, []byte, error) {
	budget := maxSize - protocol.ByteCount(overhead)
	if !onlyAck {
		if random, ok := p.uSpec.InitialPacketSpec.FrameBuilder.(*QUICRandomFrames); ok {
			// Каждый CRYPTO добавляет type и два varint длиной не более восьми
			// байт; исходный единственный заголовок уже учтён базовым packer.
			budget -= protocol.ByteCount(max(random.MinPING, random.MaxPING)) + protocol.ByteCount(max(random.MinCRYPTO, random.MaxCRYPTO))*(1+8+8)
		}
		if budget <= p.getLongHeader(protocol.EncryptionInitial, v).GetLength(v)+17 {
			return nil, payload{}, nil, fmt.Errorf("QUIC Initial frame layout does not fit datagram budget %d", maxSize)
		}
	}
	hdr, pl := p.maybeGetCryptoPacket(budget, protocol.EncryptionInitial, now, onlyAck, true, v)
	// Большой ACK может занять остаток после резервирования заголовков.
	// PopCryptoFrame тогда не извлекает данные; отправляем ACK отдельно.
	if len(pl.frames) == 1 {
		if crypto, ok := pl.frames[0].Frame.(*wire.CryptoFrame); ok && len(crypto.Data) == 0 {
			pl.length -= crypto.Length(v)
			pl.frames = nil
		}
	}
	if pl.length > 0 && hdr.GetLength(v)+pl.length+protocol.ByteCount(overhead) > maxSize {
		return nil, payload{}, nil, fmt.Errorf("QUIC Initial frames exceed datagram budget %d", maxSize)
	}
	if pl.length == 0 || onlyAck || len(pl.frames) == 0 {
		return hdr, pl, nil, nil
	}
	if p.initialDatagramMinSize() > maxSize {
		return nil, payload{}, nil, fmt.Errorf("QUIC Initial minimum datagram size %d exceeds budget %d", p.initialDatagramMinSize(), maxSize)
	}
	data, err := p.MarshalInitialPacketPayload(pl, maxSize-hdr.GetLength(v)-protocol.ByteCount(overhead), v)
	if err == nil {
		// Header protection требует минимум четыре байта PN + plaintext.
		for len(data)+int(hdr.PacketNumberLen) < 4 {
			data = append(data, 0)
		}
	}
	return hdr, pl, data, err
}

func (p *uPacketPacker) initialDatagramMinSize() protocol.ByteCount {
	if p.uSpec.UDPDatagramMinSize != 0 {
		return protocol.ByteCount(p.uSpec.UDPDatagramMinSize)
	}
	return DefaultUDPDatagramMinSize
}

func (p *uPacketPacker) padInitialDatagram(buffer *packetBuffer) {
	// UDP padding находится после всех длинных пакетов, чтобы не скрыть
	// следующий coalesced packet от parser получателя.
	if padding := p.initialDatagramMinSize() - buffer.Len(); padding > 0 {
		buffer.Data = append(buffer.Data, make([]byte, padding)...)
	}
}

func (p *uPacketPacker) appendInitialPacket(buffer *packetBuffer, header *wire.ExtendedHeader, pl payload, uPayload []byte, encLevel protocol.EncryptionLevel, sealer sealer, v protocol.Version) (*longHeaderPacket, error) {

	pnLen := protocol.ByteCount(header.PacketNumberLen)
	header.Length = pnLen + protocol.ByteCount(sealer.Overhead()) + protocol.ByteCount(len(uPayload))

	startLen := len(buffer.Data)
	raw := buffer.Data[startLen:] // [UQUIC] the raw here is a sub-slice of buffer.Data, latter's len < size

	raw, err := header.Append(raw, v)
	if err != nil {
		return nil, err
	}
	payloadOffset := protocol.ByteCount(len(raw))
	raw = append(raw, uPayload...)

	// fmt.Printf("Payload: %x\n", raw[payloadOffset:])

	// fmt.Printf("Pre-Encryption: %x\n", raw)

	raw = p.encryptPacket(raw, sealer, header.PacketNumber, payloadOffset, pnLen)
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	// fmt.Printf("Post-Encryption: %x\n", raw)

	if pn := p.pnManager.PopPacketNumber(encLevel); pn != header.PacketNumber {
		return nil, fmt.Errorf("packetPacker BUG: Peeked and Popped packet numbers do not match: expected %d, got %d", pn, header.PacketNumber)
	}
	return &longHeaderPacket{
		header:       header,
		ack:          pl.ack,
		frames:       pl.frames,
		streamFrames: pl.streamFrames,
		length:       protocol.ByteCount(len(raw)),
	}, nil
}

func (p *uPacketPacker) MarshalInitialPacketPayload(pl payload, maxSize protocol.ByteCount, v protocol.Version) ([]byte, error) {
	var originalFrameBytes []byte
	var preserved []byte
	var err error
	if pl.ack != nil {
		preserved, err = pl.ack.Append(preserved, v)
		if err != nil {
			return nil, err
		}
	}

	for _, f := range pl.frames {
		var err error
		if _, ok := f.Frame.(*wire.CryptoFrame); !ok {
			preserved, err = f.Frame.Append(preserved, v)
			if err != nil {
				return nil, err
			}
			continue
		}

		originalFrameBytes, err = f.Frame.Append(originalFrameBytes, v)
		if err != nil {
			return nil, err
		}
	}

	// ACK и управляющие фреймы сохраняются вместе с CRYPTO, включая PTO без данных.
	if len(originalFrameBytes) == 0 {
		if protocol.ByteCount(len(preserved)) > maxSize {
			return nil, fmt.Errorf("QUIC Initial control frames exceed payload budget %d", maxSize)
		}
		return preserved, nil
	}
	qchframes, err := readQUICFrames(originalFrameBytes)
	if err != nil {
		return nil, err
	}

	// parse crypto data
	cryptoData, err := clienthellod.ReassembleCRYPTOFrames(qchframes)
	if err != nil {
		return nil, err
	}

	builder := p.uSpec.InitialPacketSpec.FrameBuilder
	if random, ok := builder.(*QUICRandomFrames); ok {
		// PADDING использует оставшееся место; данные и количество CRYPTO/PING
		// сохраняются. Спецификация не меняется и безопасна для повторного Dial.
		copy := *random
		available := maxSize - protocol.ByteCount(len(preserved))
		if available < 0 {
			return nil, fmt.Errorf("QUIC Initial control frames exceed payload budget %d", maxSize)
		}
		if protocol.ByteCount(copy.Length) > available {
			copy.Length = uint16(available)
		}
		builder = &copy
	}
	var encoded []byte
	if qf, ok := builder.(QUICFrames); builder == nil || ok && len(qf) == 0 {
		qfs := QUICFrames{}
		for _, frame := range qchframes {
			if cryptoFrame, ok := frame.(*clienthellod.CRYPTO); ok {
				qfs = append(qfs, QUICFrameCrypto{int(cryptoFrame.Offset), int(cryptoFrame.Length)})
			}
		}
		encoded, err = qfs.Build(cryptoData)
	} else if oab, ok := builder.(offsetAwareFrameBuilder); ok {
		encoded, err = oab.BuildAt(cryptoData, cryptoBaseOffset(qchframes))
	} else {
		encoded, err = builder.Build(cryptoData)
	}
	if err != nil {
		return nil, err
	}
	if protocol.ByteCount(len(preserved)+len(encoded)) > maxSize {
		return nil, fmt.Errorf("QUIC Initial frame layout exceeds payload budget %d", maxSize)
	}
	return append(preserved, encoded...), nil
}

// cryptoBaseOffset returns the lowest CRYPTO-frame offset among the given frames,
// which is the crypto-stream offset at which this packet's reassembled crypto data
// begins. Returns 0 when there are no CRYPTO frames.
func cryptoBaseOffset(frames []clienthellod.QUICFrame) uint64 {
	var base uint64
	found := false
	for _, frame := range frames {
		cf, ok := frame.(*clienthellod.CRYPTO)
		if !ok {
			continue
		}
		if !found || cf.Offset < base {
			base = cf.Offset
			found = true
		}
	}
	return base
}

func (p *uPacketPacker) MaybePackPTOProbePacket(
	encLevel protocol.EncryptionLevel,
	maxPacketSize protocol.ByteCount,
	now time.Time,
	v protocol.Version,
) (*coalescedPacket, error) {
	if encLevel == protocol.Encryption1RTT {
		s, err := p.cryptoSetup.Get1RTTSealer()
		if err != nil {
			return nil, err
		}
		kp := s.KeyPhase()
		connID := p.getDestConnID()
		pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
		hdrLen := wire.ShortHeaderLen(connID, pnLen)
		pl := p.maybeGetAppDataPacket(maxPacketSize-protocol.ByteCount(s.Overhead())-hdrLen, false, true, now, v)
		if pl.length == 0 {
			return nil, nil
		}
		buffer := getPacketBuffer()
		packet := &coalescedPacket{buffer: buffer}
		shp, err := p.appendShortHeaderPacket(buffer, connID, pn, pnLen, kp, pl, 0, maxPacketSize, s, false, v)
		if err != nil {
			return nil, err
		}
		packet.shortHdrPacket = &shp
		return packet, nil
	}

	var sealer handshake.LongHeaderSealer
	//nolint:exhaustive // Probe packets are never sent for 0-RTT.
	switch encLevel {
	case protocol.EncryptionInitial:
		var err error
		sealer, err = p.cryptoSetup.GetInitialSealer()
		if err != nil {
			return nil, err
		}
	case protocol.EncryptionHandshake:
		var err error
		sealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil {
			return nil, err
		}
	default:
		panic("unknown encryption level")
	}
	var hdr *wire.ExtendedHeader
	var pl payload
	var initialData []byte
	if encLevel == protocol.EncryptionInitial && p.uSpec != nil {
		var err error
		hdr, pl, initialData, err = p.prepareInitialPacket(maxPacketSize, sealer.Overhead(), now, false, v)
		if err != nil {
			return nil, err
		}
	} else {
		hdr, pl = p.maybeGetCryptoPacket(maxPacketSize-protocol.ByteCount(sealer.Overhead()), encLevel, now, false, true, v)
	}
	if pl.length == 0 {
		return nil, nil
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer}
	size := p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead())
	var padding protocol.ByteCount
	if encLevel == protocol.EncryptionInitial {
		if initialData == nil { // default behavior
			padding = p.initialPaddingLen(pl.frames, size, maxPacketSize)
		} else { // otherwise we resend the spec-based initial packet
			initPkt, err := p.appendInitialPacket(buffer, hdr, pl, initialData, protocol.EncryptionInitial, sealer, v)
			if err != nil {
				return nil, err
			}

			packet.longHdrPackets = []*longHeaderPacket{initPkt}
			p.padInitialDatagram(buffer)
			return packet, nil
		}
	}

	longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdr, pl, padding, encLevel, sealer, v)
	if err != nil {
		return nil, err
	}
	packet.longHdrPackets = []*longHeaderPacket{longHdrPacket}
	return packet, nil
}
