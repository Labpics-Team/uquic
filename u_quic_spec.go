package quic

import tls "github.com/refraction-networking/utls"

const (
	DefaultUDPDatagramMinSize = 1200
)

type QUICSpec struct {
	// InitialPacketSpec specifies the QUIC Initial Packet, which includes Initial
	// Packet Headers and Frames.
	InitialPacketSpec InitialPacketSpec

	// ClientHelloSpec specifies the TLS ClientHello to be sent in the first Initial
	// Packet. It is implemented by the uTLS library and a valid ClientHelloSpec
	// for QUIC MUST include (utls).QUICTransportParametersExtension.
	ClientHelloSpec *tls.ClientHelloSpec

	// UDPDatagramMinSize задаёт минимальный размер полезной нагрузки UDP; недостающие байты
	// дополняются нулями. Ноль означает DefaultUDPDatagramMinSize.
	// Если Config.InitialPacketSize не задан, UTransport выбирает начальный
	// бюджет не ниже этого размера. Явно заданный бюджет не увеличивается;
	// несовместимый размер приводит к ошибке Dial или DialEarly.
	UDPDatagramMinSize int
}

func (s *QUICSpec) UpdateConfig(config *Config) {
	s.InitialPacketSpec.UpdateConfig(config)
}
