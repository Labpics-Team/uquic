package congestion

// This file is a PURE ADDITION: a deterministic congestion-control benchmark
// harness plus a CUBIC baseline characterization. It adds ZERO production code
// and ZERO new dependencies — it only drives the existing SendAlgorithm through
// its public interface.
//
// The link model is a deliberately SIMPLIFIED single-bottleneck, store-and-forward
// model (one flow, one bottleneck link, a finite tail-drop buffer, fixed one-way
// propagation delay, fixed MTU). It is NOT a faithful reproduction of a real
// network: there is no reverse-path congestion, no ACK compression, no jitter, no
// reordering, and losses are injected on a fixed deterministic schedule rather
// than emerging from queue dynamics alone (buffer overflow loss IS modeled, but
// the {1%,3%} characterization uses a deterministic "drop every Nth packet"
// pattern so the numbers are reproducible). Its purpose is to lock CUBIC's
// CURRENT behavior as a regression baseline that a future BBRv1 sender must beat,
// not to predict absolute real-world throughput.
//
// METHODOLOGY CAVEATS (verified by isolated review 2026-06-20 — read before citing):
//   (a) The absolute B/s goldens are MODEL FIXTURES, not Mbps a real CUBIC flow would
//       deliver. Lost packets are not retransmitted and RTT is held at the queue-free
//       minimum, so the collapse magnitude is amplified and the numbers are opaque
//       fixtures of THIS harness. Trust the DIRECTION/ratio, not the absolute value.
//   (b) Constant min-RTT feedback FLATTERS CUBIC (it grows as fast as it ever could)
//       and structurally omits the shallow-buffer / RTT-rises (bufferbloat) regime,
//       where CUBIC's loss response is actually defensible. The baseline is therefore
//       biased toward making any RTT/bandwidth-probing successor (BBRv1) look good.
//   (c) When BBRv1 lands (ch.17c), assert the RELATIVE improvement + inequality
//       direction and RE-PIN fresh goldens for BBR; do NOT reuse CUBIC's absolute band
//       as BBR's target. 17c must also add a variable-RTT/bufferbloat regime so BBR's
//       win is proven where it actually matters, not only under min-RTT bias.

import (
	"testing"
	"time"

	"github.com/refraction-networking/uquic/internal/protocol"
	"github.com/refraction-networking/uquic/internal/utils"
)

// ---------------------------------------------------------------------------
// Link model parameters
// ---------------------------------------------------------------------------

// linkConfig describes a single-bottleneck link for the simulator.
type linkConfig struct {
	// bandwidthBytesPerSec is the bottleneck bandwidth in bytes/second.
	bandwidthBytesPerSec int64
	// oneWayDelay is the propagation delay in each direction.
	// The base (queue-free) RTT is 2*oneWayDelay + serialization time.
	oneWayDelay time.Duration
	// bufferBytes is the bottleneck buffer capacity in bytes. Packets that would
	// overflow this buffer are tail-dropped and reported as congestion events.
	bufferBytes protocol.ByteCount
	// mtu is the size of every data packet (and the congestion-control datagram size).
	mtu protocol.ByteCount
	// lossEveryN deterministically drops every Nth data packet to model a target
	// loss rate (e.g. N=100 -> ~1% loss). 0 means "no scheduled loss" (only buffer
	// overflow can cause loss).
	lossEveryN int
	// duration is the simulated wall-clock time the flow runs for.
	duration time.Duration
}

// bdp returns the bandwidth-delay product in bytes for the base RTT.
func (c linkConfig) bdp() protocol.ByteCount {
	rtt := 2 * c.oneWayDelay
	return protocol.ByteCount(c.bandwidthBytesPerSec) * protocol.ByteCount(rtt) / protocol.ByteCount(time.Second)
}

// serializationTime is how long the bottleneck takes to clock out one MTU.
func (c linkConfig) serializationTime() time.Duration {
	return time.Duration(int64(c.mtu) * int64(time.Second) / c.bandwidthBytesPerSec)
}

// ---------------------------------------------------------------------------
// Deterministic discrete-event simulator
// ---------------------------------------------------------------------------

// eventKind distinguishes the two scheduled event types.
type eventKind int

const (
	// eventAck is delivered to the sender when an ACK arrives back at the sender.
	eventAck eventKind = iota
	// eventLoss is delivered when a tail-dropped packet's loss is detected (one RTT later).
	eventLoss
)

// linkEvent is a scheduled future event.
type linkEvent struct {
	at           time.Time
	kind         eventKind
	packetNumber protocol.PacketNumber
}

// inFlightPacket records a packet that left the sender but has not yet been
// acked or declared lost.
type inFlightPacket struct {
	packetNumber protocol.PacketNumber
	size         protocol.ByteCount
}

// simResult is the measured outcome of a single simulation run.
type simResult struct {
	ackedBytes    protocol.ByteCount
	sentPackets   int
	lostPackets   int
	simDuration   time.Duration
	goodputBytesS int64 // ackedBytes / simDuration, in bytes/second
}

// runLinkSim drives the supplied SendAlgorithm through one deterministic flow.
//
// The function is fully deterministic: given the same sender configuration and
// linkConfig it produces byte-identical results on every run. It uses only the
// injected mockClock — never time.Now — and never any randomness.
func runLinkSim(sender SendAlgorithm, rttStats *utils.RTTStats, clock *mockClock, cfg linkConfig) simResult {
	const ackDelay = 0

	baseRTT := 2*cfg.oneWayDelay + cfg.serializationTime()
	serialization := cfg.serializationTime()

	// Seed the RTT estimate so the pacer has a finite bandwidth estimate from the
	// first send. Without a measured RTT, BandwidthEstimate() returns infBandwidth
	// and pacing is effectively disabled.
	rttStats.UpdateRTT(baseRTT, ackDelay)

	// bottleneckFreeAt is the time the bottleneck finishes clocking out the last
	// admitted packet. The number of bytes currently queued is derived from how
	// far this lies in the future relative to "now".
	bottleneckFreeAt := clock.Now()

	inFlight := map[protocol.PacketNumber]inFlightPacket{}
	var bytesInFlight protocol.ByteCount

	// events is a time-ordered slice acting as a simple priority queue. Inserts
	// keep it sorted by time so the head is always the next event.
	var events []linkEvent
	insertEvent := func(ev linkEvent) {
		i := 0
		for i < len(events) && !events[i].at.After(ev.at) {
			i++
		}
		events = append(events, linkEvent{})
		copy(events[i+1:], events[i:])
		events[i] = ev
	}

	var dataPacketCounter int
	var res simResult
	res.simDuration = cfg.duration
	endTime := clock.Now().Add(cfg.duration)

	// sendOne attempts to clock a single packet onto the link at the current time.
	// Returns true if a packet was actually admitted to the sender's send window.
	sendOne := func(pn protocol.PacketNumber) {
		now := clock.Now()
		sender.OnPacketSent(now, bytesInFlight, pn, cfg.mtu, true)
		inFlight[pn] = inFlightPacket{packetNumber: pn, size: cfg.mtu}
		bytesInFlight += cfg.mtu
		res.sentPackets++
		dataPacketCounter++

		// Decide tail-drop vs admission at the bottleneck.
		// Queue length in bytes = bytes still waiting to be clocked out.
		var queued protocol.ByteCount
		if bottleneckFreeAt.After(now) {
			queued = protocol.ByteCount(bottleneckFreeAt.Sub(now)) * protocol.ByteCount(cfg.bandwidthBytesPerSec) / protocol.ByteCount(time.Second)
		}

		dropped := false
		if cfg.lossEveryN > 0 && dataPacketCounter%cfg.lossEveryN == 0 {
			dropped = true // scheduled deterministic loss
		} else if queued+cfg.mtu > cfg.bufferBytes {
			dropped = true // tail drop on buffer overflow
		}

		if dropped {
			// Loss is detected one base RTT after the packet would have been acked.
			insertEvent(linkEvent{at: now.Add(baseRTT), kind: eventLoss, packetNumber: pn})
			return
		}

		// Admit to the bottleneck: it departs after serialization (queued behind
		// whatever is already in the bottleneck), then propagates to the receiver
		// and the ACK propagates back.
		departBase := now
		if bottleneckFreeAt.After(departBase) {
			departBase = bottleneckFreeAt
		}
		departAt := departBase.Add(serialization)
		bottleneckFreeAt = departAt
		ackAt := departAt.Add(2 * cfg.oneWayDelay)
		insertEvent(linkEvent{at: ackAt, kind: eventAck, packetNumber: pn})
	}

	nextPacketNumber := protocol.PacketNumber(1)

	// pumpSends sends as many packets as pacing and the congestion window allow at
	// the current instant.
	pumpSends := func() {
		for clock.Now().Before(endTime) {
			if !sender.CanSend(bytesInFlight) {
				return
			}
			if !sender.HasPacingBudget(clock.Now()) {
				return
			}
			sendOne(nextPacketNumber)
			nextPacketNumber++
		}
	}

	// Prime the pump at t=0.
	pumpSends()

	for len(events) > 0 {
		ev := events[0]
		events = events[1:]

		if ev.at.After(endTime) {
			// Stop processing events past the measurement window.
			break
		}

		// Advance the simulated clock to the event time.
		if ev.at.After(clock.Now()) {
			clock.Advance(ev.at.Sub(clock.Now()))
		}

		pkt, tracked := inFlight[ev.packetNumber]
		if !tracked {
			continue
		}

		priorInFlight := bytesInFlight

		switch ev.kind {
		case eventAck:
			delete(inFlight, ev.packetNumber)
			bytesInFlight -= pkt.size
			// Feed a fresh RTT sample. The base RTT is used (queueing delay is
			// folded into the bottleneck timing already); this keeps the smoothed
			// RTT finite and stable so pacing stays enabled.
			rttStats.UpdateRTT(baseRTT, ackDelay)
			sender.MaybeExitSlowStart()
			sender.OnPacketAcked(ev.packetNumber, pkt.size, priorInFlight, clock.Now())
			res.ackedBytes += pkt.size
		case eventLoss:
			delete(inFlight, ev.packetNumber)
			bytesInFlight -= pkt.size
			sender.OnCongestionEvent(ev.packetNumber, pkt.size, priorInFlight)
			res.lostPackets++
		}

		// After every event, try to send more.
		pumpSends()

		// If the sender is pacing-limited (window open but no budget yet), advance
		// to the next time a packet may be sent so the flow does not stall.
		if len(events) == 0 && sender.CanSend(bytesInFlight) {
			t := sender.TimeUntilSend(bytesInFlight)
			if !t.IsZero() && t.After(clock.Now()) && t.Before(endTime) {
				clock.Advance(t.Sub(clock.Now()))
				pumpSends()
			}
		}
	}

	if cfg.duration > 0 {
		res.goodputBytesS = int64(res.ackedBytes) * int64(time.Second) / int64(cfg.duration)
	}
	return res
}

// newBenchSender constructs a fresh CUBIC sender wired to the supplied clock and
// rttStats, mirroring the construction in cubic_sender_test.go.
func newBenchSender(clock *mockClock, rttStats *utils.RTTStats, mtu protocol.ByteCount) *cubicSender {
	return newCubicSender(
		clock,
		rttStats,
		false, /* reno=false -> real CUBIC */
		mtu,
		initialCongestionWindowPackets*mtu,
		MaxCongestionWindow,
		nil,
	)
}

// runCubicGoodput sets up and runs one CUBIC simulation for the given loss
// schedule, returning the measured goodput in bytes/second. Everything is
// constructed fresh so runs are independent and deterministic.
func runCubicGoodput(lossEveryN int) simResult {
	const (
		bandwidthBytesPerSec = 10_000_000 / 8 // 10 Mbps -> 1_250_000 bytes/s
		oneWayDelay          = 50 * time.Millisecond
		simDuration          = 30 * time.Second
	)
	mtu := protocol.ByteCount(protocol.InitialPacketSize)

	clock := &mockClock{}
	rttStats := &utils.RTTStats{}
	sender := newBenchSender(clock, rttStats, mtu)

	cfg := linkConfig{
		bandwidthBytesPerSec: bandwidthBytesPerSec,
		oneWayDelay:          oneWayDelay,
		mtu:                  mtu,
		lossEveryN:           lossEveryN,
		duration:             simDuration,
	}
	// Bottleneck buffer = 1x BDP, a common "single BDP" sizing.
	cfg.bufferBytes = cfg.bdp()

	return runLinkSim(sender, rttStats, clock, cfg)
}

// lossEveryNFor converts a target fractional loss rate into the deterministic
// "drop every Nth packet" parameter. 0 loss -> 0 (no scheduled drops).
func lossEveryNFor(rate float64) int {
	if rate <= 0 {
		return 0
	}
	return int(1.0/rate + 0.5)
}

// ---------------------------------------------------------------------------
// Characterization test: lock CUBIC's current goodput as a regression baseline
// ---------------------------------------------------------------------------

func TestCubicGoodputCharacterization(t *testing.T) {
	// GOLDEN ranges lock the CURRENT measured CUBIC behavior of this harness.
	// They were derived by the RED->GREEN procedure documented in the chapter
	// report: first asserting an obviously-wrong value (confirming the test can
	// fail), then pinning the measured value with a tolerance band. The +/- band
	// absorbs only integer-rounding wobble in the model; the simulation itself is
	// fully deterministic, so in practice the measured value is constant.
	cases := []struct {
		name      string
		lossRate  float64
		minBytesS int64
		maxBytesS int64
	}{
		// Golden ranges pin the measured CUBIC goodput (bytes/s) with a tolerance
		// band. Measured values for this harness:
		//   0% loss -> 1_207_594 B/s (9.66 Mbps, near the 10 Mbps link capacity)
		//   1% loss ->   143_744 B/s (1.15 Mbps, CUBIC collapses under loss)
		//   3% loss ->    84_394 B/s (0.68 Mbps, collapses further)
		// The simulation is fully deterministic (verified by
		// TestCubicGoodputDeterministic), so the measured value is constant. The
		// band is intentionally generous (~+/-15%) so a future Go or CUBIC
		// patch-level change in growth math nudges, rather than shatters, the
		// baseline — while still catching any real regression (e.g. a sender that
		// stops collapsing under loss, which is precisely what BBRv1 must do).
		// Bands are tightened toward the byte-deterministic measured values (a small
		// ~5-10% margin is kept only to absorb Go/CUBIC patch-level float-rounding
		// across CI platforms, NOT runtime wobble — the sim is proven deterministic by
		// TestCubicGoodputDeterministic). Tight upper ceilings are deliberate: they
		// catch a PARTIAL loss-resilience regression (e.g. 3% goodput creeping up),
		// not only a total "stopped collapsing" one.
		{name: "0pct_loss", lossRate: 0.00, minBytesS: 1_140_000, maxBytesS: 1_270_000},
		{name: "1pct_loss", lossRate: 0.01, minBytesS: 130_000, maxBytesS: 158_000},
		{name: "3pct_loss", lossRate: 0.03, minBytesS: 76_000, maxBytesS: 93_000},
	}

	results := map[string]int64{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCubicGoodput(lossEveryNFor(tc.lossRate))
			results[tc.name] = res.goodputBytesS
			t.Logf("loss=%.0f%%  goodput=%d bytes/s (%.2f Mbps)  acked=%d sent=%d lost=%d",
				tc.lossRate*100,
				res.goodputBytesS,
				float64(res.goodputBytesS)*8/1e6,
				res.ackedBytes, res.sentPackets, res.lostPackets,
			)
			if res.goodputBytesS < tc.minBytesS || res.goodputBytesS > tc.maxBytesS {
				t.Errorf("goodput %d bytes/s outside golden range [%d, %d]",
					res.goodputBytesS, tc.minBytesS, tc.maxBytesS)
			}
		})
	}

	// Qualitative invariant: CUBIC collapses under loss. Goodput at 3% loss must
	// be materially below the lossless case. This is exactly the property a future
	// BBRv1 sender is expected to fix, so it must hold for the baseline.
	zero := results["0pct_loss"]
	three := results["3pct_loss"]
	if zero == 0 || three == 0 {
		t.Fatalf("missing measurements: 0%%=%d 3%%=%d", zero, three)
	}
	if three >= zero {
		t.Errorf("expected 3%% loss goodput (%d) to be below 0%% loss goodput (%d)", three, zero)
	}
	// "Materially below" — at least a 20%% reduction.
	if three > zero*80/100 {
		t.Errorf("expected CUBIC to collapse under 3%% loss: 3%%=%d is not materially below 0%%=%d", three, zero)
	}
}

// TestCubicGoodputDeterministic verifies the simulator is deterministic:
// the same inputs must yield byte-identical goodput on every run.
func TestCubicGoodputDeterministic(t *testing.T) {
	for _, lossRate := range []float64{0.00, 0.01, 0.03} {
		n := lossEveryNFor(lossRate)
		first := runCubicGoodput(n).goodputBytesS
		for i := 0; i < 4; i++ {
			got := runCubicGoodput(n).goodputBytesS
			if got != first {
				t.Fatalf("non-deterministic goodput at loss=%.0f%%: run0=%d run%d=%d",
					lossRate*100, first, i+1, got)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Benchmark wrapper for ad-hoc runs (go test -bench BenchmarkCubicGoodput)
// ---------------------------------------------------------------------------

func BenchmarkCubicGoodput(b *testing.B) {
	for _, bc := range []struct {
		name     string
		lossRate float64
	}{
		{"0pct_loss", 0.00},
		{"1pct_loss", 0.01},
		{"3pct_loss", 0.03},
	} {
		b.Run(bc.name, func(b *testing.B) {
			n := lossEveryNFor(bc.lossRate)
			var res simResult
			for i := 0; i < b.N; i++ {
				res = runCubicGoodput(n)
			}
			b.ReportMetric(float64(res.goodputBytesS), "goodput_bytes/s")
			b.ReportMetric(float64(res.goodputBytesS)*8/1e6, "goodput_Mbps")
		})
	}
}
