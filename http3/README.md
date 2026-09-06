# HTTP/3 — справка

Пакет содержит HTTP/3-клиент и сервер. Клиентский `Transport` реализует
`http.RoundTripper`; поле конфигурации называется `QUICConfig`.
`RoundTripper` сохранён как deprecated alias `Transport`. Функции
`GetURoundTripper` в текущем пакете нет.

Точную поверхность текущего checkout получайте из исходников:

```sh
go doc ./http3 Transport
go doc ./http3 Transport.Dial
go doc . UTransport.DialEarly
```

`Transport.Dial` позволяет приложению предоставить собственный dial callback,
возвращающий `quic.EarlyConnection`; `UTransport.DialEarly` является
низкоуровневым uQUIC-путём. `Dial == nil` использует обычный путь HTTP/3
transport и не подключает браузерный профиль автоматически.

Время жизни ресурсов, созданных callback вне `Transport`, остаётся обязанностью
владельца этих ресурсов. Закрытие HTTP/3 transport не следует трактовать как
универсальную очистку внешнего `UTransport` или UDP socket без проверки
конкретного пути.

Сигнатуры принадлежат [`transport.go`](transport.go) и
[`u_transport.go`](../u_transport.go); этот документ не дублирует полный API.
Протокольные источники: [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114),
[RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) и
[RFC 9297](https://www.rfc-editor.org/rfc/rfc9297).
