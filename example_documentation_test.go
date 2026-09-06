package quic_test

import (
	"fmt"

	quic "github.com/refraction-networking/uquic"
)

// Пример разрешает выбранный профиль без сетевого соединения.
// Он не проверяет свежесть эталона или неотличимость от браузера.
func ExampleCurrentChromeParrot() {
	spec, err := quic.QUICID2Spec(quic.CurrentChromeParrot())
	if err != nil {
		panic(err)
	}
	fmt.Println(spec.ClientHelloSpec != nil)
	// Output: true
}
