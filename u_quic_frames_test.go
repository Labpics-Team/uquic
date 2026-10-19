package quic

import (
	"bytes"
	"errors"
	"testing"

	"github.com/refraction-networking/clienthellod"
)

func TestQUICFrames(t *testing.T) {
	resultQUICPayload, err := testQUICFrames.Build(testCryptoFrameBytes)
	if err != nil {
		t.Fatalf("Failed to build QUIC frames: %v", err)
	}

	if len(resultQUICPayload) != len(truthPayloadFromQUICFrames) {
		t.Fatalf("QUIC payload length mismatch: got %d, want %d. \n%x", len(resultQUICPayload), len(truthPayloadFromQUICFrames), resultQUICPayload)
	}

	// verify that the crypto frames would actually assemble the original crypto data
	qchframes, err := readQUICFrames(resultQUICPayload)
	if err != nil {
		t.Fatalf("Failed to read QUIC frames: %v", err)
	}

	reassembledCryptoData, err := clienthellod.ReassembleCRYPTOFrames(qchframes)
	if err != nil {
		t.Fatalf("Failed to reassemble crypto data: %v", err)
	}
	if !bytes.Equal(reassembledCryptoData, testCryptoFrameBytes) {
		t.Fatalf("Reassembled crypto data mismatch: \n%x", reassembledCryptoData)
	}
}

func TestQUICRandomFrames(t *testing.T) {
	resultQUICPayload, err := testQUICRandomFrames.Build(testCryptoFrameBytes)
	if err != nil {
		t.Fatalf("Failed to build QUIC frames: %v", err)
	}

	if len(resultQUICPayload) != 512 {
		t.Fatalf("QUIC payload length mismatch: got %d, want 512. \n%x", len(resultQUICPayload), resultQUICPayload)
	}

	// verify that the crypto frames would actually assemble the original crypto data
	qchframes, err := readQUICFrames(resultQUICPayload)
	if err != nil {
		t.Fatalf("Failed to read QUIC frames: %v", err)
	}

	reassembledCryptoData, err := clienthellod.ReassembleCRYPTOFrames(qchframes)
	if err != nil {
		t.Fatalf("Failed to reassemble crypto data: %v", err)
	}
	if !bytes.Equal(reassembledCryptoData, testCryptoFrameBytes) {
		t.Fatalf("Reassembled crypto data mismatch: \n%x", reassembledCryptoData)
	}

	// count how many PING and CRYPTO frames are in the QUIC payload
	var pingCount, cryptoCount int
	for _, frame := range qchframes {
		switch frame.FrameType() {
		case clienthellod.QUICFrame_PING:
			pingCount++
		case clienthellod.QUICFrame_CRYPTO:
			cryptoCount++
		}
	}

	if pingCount < int(testQUICRandomFrames.MinPING) || pingCount >= int(testQUICRandomFrames.MaxPING) {
		t.Fatalf("PING frame count mismatch: got %d, want [%d, %d)", pingCount, testQUICRandomFrames.MinPING, testQUICRandomFrames.MaxPING)
	}

	if cryptoCount < int(testQUICRandomFrames.MinCRYPTO) || cryptoCount >= int(testQUICRandomFrames.MaxCRYPTO) {
		t.Fatalf("CRYPTO frame count mismatch: got %d, want [%d, %d)", cryptoCount, testQUICRandomFrames.MinCRYPTO, testQUICRandomFrames.MaxCRYPTO)
	}
}

func TestQUICRandomFramesBoundedLayout(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		cryptoCount, pingCount      uint8
		base                        uint64
		dataLen, budget, wantPrefix int
		padding                     uint16
	}{
		{name: "short_frames_fit_exactly", cryptoCount: 70, dataLen: 70, budget: 286, wantPrefix: 70},
		{name: "short_frames_keep_tail", cryptoCount: 70, dataLen: 70, budget: 285, wantPrefix: 69},
		{name: "large_offset", cryptoCount: 1, pingCount: 2, base: 16384, dataLen: 200, budget: 70, wantPrefix: 62},
		{name: "before_length_varint", cryptoCount: 1, pingCount: 2, base: 16384, dataLen: 200, budget: 72, wantPrefix: 63},
		{name: "after_length_varint", cryptoCount: 1, pingCount: 2, base: 16384, dataLen: 200, budget: 73, wantPrefix: 64},
		{name: "padding_uses_remaining_budget", cryptoCount: 2, pingCount: 2, dataLen: 8, budget: 120, wantPrefix: 8, padding: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := QUICRandomFrames{
				MinCRYPTO: tc.cryptoCount, MaxCRYPTO: tc.cryptoCount,
				MinPING: tc.pingCount, MaxPING: tc.pingCount,
				MinPADDING: 3, MaxPADDING: 3, Length: tc.padding,
			}
			originalBuilder := builder
			data := bytes.Repeat([]byte{42}, tc.dataLen)
			encoded, consumed, err := builder.buildAtWithLimit(data, tc.base, tc.budget)
			if err != nil {
				t.Fatal(err)
			}
			if consumed != tc.wantPrefix || len(encoded) > tc.budget || builder != originalBuilder {
				t.Fatalf("prefix=%d, want=%d, wire=%d, budget=%d, builder=%+v", consumed, tc.wantPrefix, len(encoded), tc.budget, builder)
			}
			if tc.padding > 0 && len(encoded) != tc.budget {
				t.Fatalf("padding: got %d bytes, want %d", len(encoded), tc.budget)
			}
			frames, err := readQUICFrames(encoded)
			if err != nil {
				t.Fatal(err)
			}
			var cryptoCount, pingCount int
			for _, frame := range frames {
				switch frame.FrameType() {
				case clienthellod.QUICFrame_CRYPTO:
					cryptoCount++
				case clienthellod.QUICFrame_PING:
					pingCount++
				}
			}
			if cryptoCount != int(tc.cryptoCount) || pingCount != int(tc.pingCount) || cryptoBaseOffset(frames) != tc.base {
				t.Fatalf("CRYPTO=%d, PING=%d, base=%d", cryptoCount, pingCount, cryptoBaseOffset(frames))
			}
			prefix, err := clienthellod.ReassembleCRYPTOFrames(frames)
			if err != nil || !bytes.Equal(prefix, data[:tc.wantPrefix]) {
				t.Fatalf("reassembled prefix=%x, error=%v", prefix, err)
			}
		})
	}
}

func TestQUICRandomFramesBoundedLayoutRejectsNoProgress(t *testing.T) {
	builder := QUICRandomFrames{MinCRYPTO: 70, MaxCRYPTO: 70, MinPING: 2, MaxPING: 2}
	encoded, consumed, err := builder.buildAtWithLimit([]byte{42}, 0, 212)
	if !errors.Is(err, errInitialFrameBudget) || consumed != 0 || encoded != nil {
		t.Fatalf("encoded=%x, consumed=%d, error=%v", encoded, consumed, err)
	}
}

func TestQUICRandomFramesBoundedLayoutKeepsNonEmptySplits(t *testing.T) {
	builder := QUICRandomFrames{MinCRYPTO: 7, MaxCRYPTO: 7}
	data := bytes.Repeat([]byte{42}, 4096)
	copy(data, []byte{1, 0, 15, 252}) // Заголовок ClientHello с полным размером 4096.
	for _, budget := range []int{5000, 100} {
		for iteration := 0; iteration < 16; iteration++ {
			encoded, consumed, err := builder.buildAtWithLimit(data, 0, budget)
			if err != nil {
				t.Fatal(err)
			}
			if consumed < 7 {
				t.Fatalf("fixture has no room for seven non-empty frames: %d", consumed)
			}
			frames, err := readQUICFrames(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for _, frame := range frames {
				if crypto, ok := frame.(*clienthellod.CRYPTO); ok && crypto.Length == 0 {
					reconstructor := clienthellod.NewQUICClientHelloReconstructor()
					t.Fatalf("budget=%d prefix=%d empty CRYPTO at %d; collector: %v", budget, consumed, crypto.Offset, reconstructor.FromFrames(frames))
				}
			}
		}
	}
}

func TestQUICFrameReaderKeepsTrailingFrames(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		kinds   []uint64
	}{
		{"ping after padding", []byte{1, 6, 0, 1, 42, 0, 1}, []uint64{1, 6, 0, 1}},
		{"padding after ping", []byte{1, 6, 0, 1, 42, 1, 0}, []uint64{1, 6, 1, 0}},
		{"consecutive padding before ping", []byte{1, 6, 0, 1, 42, 0, 0, 1}, []uint64{1, 6, 0, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames, err := readQUICFrames(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			if len(frames) != len(tc.kinds) {
				t.Fatalf("frame count: got %d, want %d", len(frames), len(tc.kinds))
			}
			for i, kind := range tc.kinds {
				if frames[i].FrameType() != kind {
					t.Fatalf("frame %d: got %d, want %d", i, frames[i].FrameType(), kind)
				}
			}
			data, err := clienthellod.ReassembleCRYPTOFrames(frames)
			if err != nil || !bytes.Equal(data, []byte{42}) {
				t.Fatalf("crypto data: got %x, error %v", data, err)
			}
		})
	}
}

// TestQUICRandomFrames_SmallCryptoNoPanic is a regression test for a panic in
// QUICRandomFrames.Build: when the crypto data is small relative to the number of
// CRYPTO frames (or the padding budget relative to the number of PADDING frames),
// the per-frame length bound shrank to <= the lower bound and rand.Int was called
// with a non-positive argument, panicking with "argument to Int is <= 0". This
// surfaced on real dials (large post-quantum ClientHello split into many CRYPTO
// frames) and affected every QUICRandomFrames-based parrot, including Chrome_115.
// Build must succeed (or error) without panicking across the whole parameter space.
func TestQUICRandomFrames_SmallCryptoNoPanic(t *testing.T) {
	cases := []struct {
		name      string
		qrf       QUICRandomFrames
		cryptoLen int
	}{
		{"many crypto frames, tiny data", QUICRandomFrames{MinPING: 1, MaxPING: 4, MinCRYPTO: 8, MaxCRYPTO: 9, MinPADDING: 3, MaxPADDING: 6, Length: 1200}, 4},
		{"crypto frames equal data len", QUICRandomFrames{MinPING: 0, MaxPING: 2, MinCRYPTO: 8, MaxCRYPTO: 9, MinPADDING: 3, MaxPADDING: 6, Length: 1200}, 8},
		{"many padding frames, tiny budget", QUICRandomFrames{MinPING: 1, MaxPING: 2, MinCRYPTO: 1, MaxCRYPTO: 2, MinPADDING: 8, MaxPADDING: 9, Length: 70}, 64},
		{"chrome-146 params, small CH", QUICRandomFrames{MinPING: 1, MaxPING: 4, MinCRYPTO: 2, MaxCRYPTO: 8, MinPADDING: 3, MaxPADDING: 6, Length: 1231 - 16}, 16},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, tc.cryptoLen)
			for i := range data {
				data[i] = byte(i)
			}
			// Run many iterations: the builder is randomized, so a single pass can
			// miss the boundary that triggers the panic.
			for i := 0; i < 200; i++ {
				qrf := tc.qrf
				payload, err := qrf.Build(data)
				if err != nil {
					continue // an error is acceptable; a panic is not
				}
				frames, parseErr := readQUICFrames(payload)
				if parseErr != nil {
					t.Fatalf("parse iteration %d: %v", i, parseErr)
				}
				reassembled, reassembleErr := clienthellod.ReassembleCRYPTOFrames(frames)
				if reassembleErr != nil || !bytes.Equal(reassembled, data) {
					t.Fatalf("reassemble iteration %d: error %v, got %x, want %x", i, reassembleErr, reassembled, data)
				}
			}
		})
	}
}

var (
	testCryptoFrameBytes = []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23,
		0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b,
		0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f,
	} // 64 bytes

	testQUICFrames = QUICFrames{
		// first 64 bytes: 01 + 63 bytes of padding
		&QUICFramePing{},
		&QUICFramePadding{Length: 63},
		// second 64 bytes: last 32 bytes of crypto frame + 29 bytes of padding
		&QUICFrameCrypto{
			Offset: 32,
			Length: 0,
		},
		&QUICFramePadding{Length: 29},
		// third 64 bytes: first 16 bytes of crypto frame + 45 bytes of padding
		&QUICFrameCrypto{
			Offset: 0,
			Length: 16,
		},
		&QUICFramePadding{Length: 45},
		// fourth 64 bytes: second 16 bytes of crypto frame + 45 bytes of padding
		&QUICFrameCrypto{
			Offset: 16,
			Length: 16,
		},
		&QUICFramePadding{Length: 45},
	}

	truthPayloadFromQUICFrames = []byte{
		0x01, // ping
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 63 bytes of padding
		0x06, 0x20, 0x20, // 3 bytes header
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, // 32 bytes of crypto frame
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, // 29 bytes of padding
		0x06, 0x00, 0x10, // 3 bytes header
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // 16 bytes of crypto frame
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, // 45 bytes of padding
		0x06, 0x10, 0x10, // 3 bytes header
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, // 16 bytes of crypto frame
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, // 45 bytes of padding
	}

	testQUICRandomFrames = QUICRandomFrames{
		MinPING:    2,
		MaxPING:    8,
		MinCRYPTO:  2,
		MaxCRYPTO:  8,
		MinPADDING: 4,
		MaxPADDING: 5,
		Length:     512,
	}
)
