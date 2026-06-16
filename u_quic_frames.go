package quic

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math"
	"math/big"
	mrand "math/rand"

	"github.com/refraction-networking/clienthellod"
	"github.com/refraction-networking/uquic/quicvarint"
)

type QUICFrameBuilder interface {
	// Build ingests data from crypto frames without the crypto frame header
	// and returns the byte representation of all frames.
	Build(cryptoData []byte) (allFrames []byte, err error)
}

// offsetAwareFrameBuilder is an optional extension of QUICFrameBuilder for builders
// that can place their CRYPTO frames at a non-zero base offset in the crypto stream.
// This is required for ClientHellos that span multiple Initial packets (e.g. the
// post-quantum X25519MLKEM768 ClientHello, which exceeds a single QUIC datagram):
// the second and later packets carry crypto data starting at a non-zero offset, and
// emitting it at offset 0 would corrupt the server-side reassembly. Builders that do
// not implement this are only correct for single-packet (offset 0) ClientHellos.
type offsetAwareFrameBuilder interface {
	QUICFrameBuilder

	// BuildAt behaves like Build but treats cryptoData as starting at baseOffset in
	// the crypto stream, so every emitted CRYPTO frame carries an absolute offset of
	// baseOffset plus its position within cryptoData.
	BuildAt(cryptoData []byte, baseOffset uint64) (allFrames []byte, err error)
}

// QUICFrames is a slice of QUICFrame that implements QUICFrameBuilder.
// It could be used to deterministically build QUIC Frames from crypto data.
type QUICFrames []QUICFrame

// Build ingests data from crypto frames without the crypto frame header
// and returns the byte representation of all frames as specified in
// the slice.
func (qfs QUICFrames) Build(cryptoData []byte) (payload []byte, err error) {
	if len(qfs) == 0 { // If no frames specified, send a single crypto frame
		qfsCryptoOnly := QUICFrames{QUICFrameCrypto{0, 0}}
		return qfsCryptoOnly.Build(cryptoData)
	}

	// lowestOffset is the base crypto-stream offset for this packet, used to map an
	// absolute CRYPTO offset back to an index into cryptoData. Only CRYPTO frames carry
	// a meaningful offset; PADDING/PING report 0 via CryptoFrameInfo and must be
	// excluded, otherwise they would pin lowestOffset to 0 and corrupt the index math
	// for multi-packet ClientHellos where the base offset is non-zero.
	lowestOffset := math.MaxInt
	for _, frame := range qfs {
		if offset, _, cryptoOK := frame.CryptoFrameInfo(); cryptoOK && offset < lowestOffset {
			lowestOffset = offset
		}
	}
	if lowestOffset == math.MaxInt {
		lowestOffset = 0 // no CRYPTO frames present
	}

	for _, frame := range qfs {
		var frameBytes []byte
		if offset, length, cryptoOK := frame.CryptoFrameInfo(); cryptoOK {
			lengthOffset := offset - lowestOffset
			if length == 0 {
				// calculate length: from offset to the end of cryptoData
				length = len(cryptoData) - lengthOffset
			}
			frameBytes = []byte{0x06} // CRYPTO frame type
			frameBytes = quicvarint.Append(frameBytes, uint64(offset))
			frameBytes = quicvarint.Append(frameBytes, uint64(length))
			frameCryptoData := make([]byte, length)
			copy(frameCryptoData, cryptoData[lengthOffset:]) // copy at most length bytes
			frameBytes = append(frameBytes, frameCryptoData...)
		} else { // Handle none crypto frames: read and append to payload
			frameBytes, err = frame.Read()
			if err != nil {
				return nil, err
			}
		}
		payload = append(payload, frameBytes...)
	}
	return payload, nil
}

// BuildFromFrames ingests data from all input frames and returns the byte representation
// of all frames as specified in the slice.
func (qfs QUICFrames) BuildFromFrames(frames []byte) (payload []byte, err error) {
	// parse frames
	r := bytes.NewReader(frames)
	qchframes, err := clienthellod.ReadAllFrames(r)
	if err != nil {
		return nil, err
	}

	// parse crypto data
	cryptoData, err := clienthellod.ReassembleCRYPTOFrames(qchframes)
	if err != nil {
		return nil, err
	}

	// marshal
	return qfs.Build(cryptoData)
}

// QUICFrame is the interface for all QUIC frames to be included in the Initial Packet.
type QUICFrame interface {
	// None crypto frames should return false for cryptoOK
	CryptoFrameInfo() (offset, length int, cryptoOK bool)

	// None crypto frames should return the byte representation of the frame.
	// Crypto frames' behavior is undefined and unused.
	Read() ([]byte, error)
}

// QUICFrameCrypto is used to specify the crypto frames containing the TLS ClientHello
// to be sent in the first Initial packet.
type QUICFrameCrypto struct {
	// Offset is used to specify the starting offset of the crypto frame.
	// Used when sending multiple crypto frames in a single packet.
	//
	// Multiple crypto frames in a single packet must not overlap and must
	// make up an entire crypto stream continuously.
	Offset int

	// Length is used to specify the length of the crypto frame.
	//
	// Must be set if it is NOT the last crypto frame in a packet.
	Length int
}

// CryptoFrameInfo() implements the QUICFrame interface.
//
// Crypto frames are later replaced by the crypto message using the information
// returned by this function.
func (q QUICFrameCrypto) CryptoFrameInfo() (offset, length int, cryptoOK bool) {
	return q.Offset, q.Length, true
}

// Read() implements the QUICFrame interface.
//
// Crypto frames are later replaced by the crypto message, so they are not Read()-able.
func (q QUICFrameCrypto) Read() ([]byte, error) {
	return nil, errors.New("crypto frames are not Read()-able")
}

// QUICFramePadding is used to specify the padding frames to be sent in the first Initial
// packet.
type QUICFramePadding struct {
	// Length is used to specify the length of the padding frame.
	Length int
}

// CryptoFrameInfo() implements the QUICFrame interface.
func (q QUICFramePadding) CryptoFrameInfo() (offset, length int, cryptoOK bool) {
	return 0, 0, false
}

// Read() implements the QUICFrame interface.
//
// Padding simply returns a slice of bytes of the specified length filled with 0.
func (q QUICFramePadding) Read() ([]byte, error) {
	return make([]byte, q.Length), nil
}

// QUICFramePing is used to specify the ping frames to be sent in the first Initial
// packet.
type QUICFramePing struct{}

// CryptoFrameInfo() implements the QUICFrame interface.
func (q QUICFramePing) CryptoFrameInfo() (offset, length int, cryptoOK bool) {
	return 0, 0, false
}

// Read() implements the QUICFrame interface.
//
// Ping simply returns a slice of bytes of size 1 with value 0x01(PING).
func (q QUICFramePing) Read() ([]byte, error) {
	return []byte{0x01}, nil
}

// QUICRandomFrames could be used to indeterministically build QUIC Frames from
// crypto data. A caller may specify how many PING and CRYPTO frames are expected
// to be included in the Initial Packet, as well as the total length plus PADDING
// frames in the end.
type QUICRandomFrames struct {
	// MinPING specifies the inclusive lower bound of the number of PING frames to be
	// included in the Initial Packet.
	MinPING uint8

	// MaxPING specifies the exclusive upper bound of the number of PING frames to be
	// included in the Initial Packet. It must be at least MinPING+1.
	MaxPING uint8

	// MinCRYPTO specifies the inclusive lower bound of the number of CRYPTO frames to
	// split the Crypto data into. It must be at least 1.
	MinCRYPTO uint8

	// MaxCRYPTO specifies the exclusive upper bound of the number of CRYPTO frames to
	// split the Crypto data into. It must be at least MinCRYPTO+1.
	MaxCRYPTO uint8

	// MinPADDING specifies the inclusive lower bound of the number of PADDING frames
	// to be included in the Initial Packet. It must be at least 1 if Length is not 0.
	MinPADDING uint8

	// MaxPADDING specifies the exclusive upper bound of the number of PADDING frames
	// to be included in the Initial Packet. It must be at least MinPADDING+1 if
	// Length is not 0.
	MaxPADDING uint8

	// Length specifies the total length of all frames including PADDING frames.
	// If the Length specified is already exceeded by the CRYPTO+PING frames, no
	// PADDING frames will be included.
	Length uint16 // 2 bytes, max 65535
}

// Build ingests data from crypto frames without the crypto frame header
// and returns the byte representation of all frames as specified in
// the slice. cryptoData is assumed to start at offset 0 in the crypto stream.
func (qrf *QUICRandomFrames) Build(cryptoData []byte) (payload []byte, err error) {
	return qrf.BuildAt(cryptoData, 0)
}

// BuildAt is like Build but treats cryptoData as starting at baseOffset in the
// crypto stream, so every emitted CRYPTO frame carries an absolute offset of
// baseOffset plus its position within cryptoData. This makes the builder correct
// for multi-packet ClientHellos (the later Initial packets carry a non-zero
// crypto-stream offset).
func (qrf *QUICRandomFrames) BuildAt(cryptoData []byte, baseOffset uint64) (payload []byte, err error) {
	// check all bounds
	if qrf.MinPING > qrf.MaxPING {
		return nil, errors.New("MinPING must be less than or equal to MaxPING")
	}
	if qrf.MinCRYPTO < 1 {
		return nil, errors.New("MinCRYPTO must be at least 1")
	}
	if qrf.MinCRYPTO > qrf.MaxCRYPTO {
		return nil, errors.New("MinCRYPTO must be less than or equal to MaxCRYPTO")
	}
	if qrf.MinPADDING < 1 && qrf.Length != 0 {
		return nil, errors.New("MinPADDING must be at least 1 if Length is not 0")
	}
	if qrf.MinPADDING > qrf.MaxPADDING && qrf.Length != 0 {
		return nil, errors.New("MinPADDING must be less than or equal to MaxPADDING if Length is not 0")
	}

	var frameList QUICFrames = make([]QUICFrame, 0)

	var cryptoSafeRandUint64 = func(min, max uint64) (uint64, error) { //nolint:revive // min/max read clearer than the suggested alternatives here
		// When the range is empty or inverted (max <= min) there is exactly one
		// valid value: min. Returning it avoids calling rand.Int with a non-positive
		// bound, which panics ("argument to Int is <= 0"). This happens legitimately
		// when the remaining crypto/padding budget shrinks to the number of frames
		// still to emit, so it must be handled rather than treated as an error.
		if max <= min {
			return min, nil
		}
		minMaxDiff := big.NewInt(int64(max - min))
		offset, err := rand.Int(rand.Reader, minMaxDiff)
		if err != nil {
			return 0, err
		}
		return min + offset.Uint64(), nil
	}

	// determine number of PING frames with crypto.rand
	numPING, err := cryptoSafeRandUint64(uint64(qrf.MinPING), uint64(qrf.MaxPING))
	if err != nil {
		return nil, err
	}

	// append PING frames
	for i := uint64(0); i < numPING; i++ {
		frameList = append(frameList, QUICFramePing{})
	}

	// determine number of CRYPTO frames with crypto.rand
	numCRYPTO, err := cryptoSafeRandUint64(uint64(qrf.MinCRYPTO), uint64(qrf.MaxCRYPTO))
	if err != nil {
		return nil, err
	}

	lenCryptoData := uint64(len(cryptoData))
	offsetCryptoData := uint64(0)
	for i := uint64(0); i < numCRYPTO-1; i++ { // select n-1 times, since the last one must be the remaining
		// randomly select length of CRYPTO frame.
		// Length must be at least 1 byte and at most the remaining length of cryptoData
		// minus 1 byte reserved for each of the CRYPTO frames still to be emitted after
		// this one (numCRYPTO-i-2 of them). Compute the upper bound with subSat so an
		// over-subscribed split (more frames than bytes) can never wrap uint64 negative
		// and panic — it simply yields max == 1 and degrades to 1-byte frames.
		maxLenCRYPTO := subSat(lenCryptoData, numCRYPTO-i-2)
		lenCRYPTO, err := cryptoSafeRandUint64(1, maxLenCRYPTO)
		if err != nil {
			return nil, err
		}
		if lenCRYPTO > lenCryptoData {
			lenCRYPTO = lenCryptoData // never read past the available crypto data
		}
		frameList = append(frameList, QUICFrameCrypto{Offset: int(baseOffset + offsetCryptoData), Length: int(lenCRYPTO)})
		offsetCryptoData += lenCRYPTO
		lenCryptoData -= lenCRYPTO
	}

	// append the last CRYPTO frame
	frameList = append(frameList, QUICFrameCrypto{Offset: int(baseOffset + offsetCryptoData), Length: 0}) // 0 means the remaining

	// dry-run to determine the total length of all frames so far
	dryrunPayload, err := frameList.Build(cryptoData)
	if err != nil {
		return nil, err
	}

	// determine length of PADDING frames to append
	lenPADDINGsigned := int64(qrf.Length) - int64(len(dryrunPayload))
	if lenPADDINGsigned > 0 {
		lenPADDING := uint64(lenPADDINGsigned)
		// determine number of PADDING frames to append
		numPADDING, err := cryptoSafeRandUint64(uint64(qrf.MinPADDING), uint64(qrf.MaxPADDING))
		if err != nil {
			return nil, err
		}

		for i := uint64(0); i < numPADDING-1; i++ { // select n-1 times, since the last one must be the remaining
			// randomly select length of PADDING frame.
			// Length must be at least 1 byte and at most the remaining padding budget
			// minus 1 byte reserved for each PADDING frame still to be emitted after this
			// one. Use subSat so an over-subscribed split cannot wrap uint64 negative.
			maxLenPADDING := subSat(lenPADDING, numPADDING-i-2)
			lenPADDINGFrame, err := cryptoSafeRandUint64(1, maxLenPADDING)
			if err != nil {
				return nil, err
			}
			if lenPADDINGFrame > lenPADDING {
				lenPADDINGFrame = lenPADDING
			}
			frameList = append(frameList, QUICFramePadding{Length: int(lenPADDINGFrame)})
			lenPADDING -= lenPADDINGFrame
		}

		// append the last CRYPTO frame
		frameList = append(frameList, QUICFramePadding{Length: int(lenPADDING)}) // 0 means the remaining
	}

	// shuffle the frameList
	mrand.Shuffle(len(frameList), func(i, j int) {
		frameList[i], frameList[j] = frameList[j], frameList[i]
	})

	// build the payload
	return frameList.Build(cryptoData)
}

// subSat returns a-b, saturating at 0 instead of wrapping when b > a. Used to
// compute per-frame length bounds without uint64 underflow when a frame split is
// over-subscribed (more frames requested than bytes available).
func subSat(a, b uint64) uint64 {
	if b >= a {
		return 0
	}
	return a - b
}
