# HTTP/3 — транспорт и справка

Пакет содержит HTTP/3-клиент и сервер. Клиентский `Transport` реализует
`http.RoundTripper`; поле `QUICConfig` имеет именно такое написание.
`RoundTripper` сохранён как устаревший alias `Transport`, но функции
`GetURoundTripper` в текущем пакете нет.

Точный API этой версии читайте из исходников, используя toolchain из
[go.mod](../go.mod). Команды выполняются из корня репозитория:

```sh
go doc ./http3 Transport
go doc ./http3 Transport.Dial
go doc . UTransport.DialEarly
```

Для настройки uQUIC клиент предоставляет `Transport.Dial`, который возвращает
`quic.EarlyConnection`, например через `UTransport.DialEarly` с выбранной
`QUICSpec`. Сигнатура callback принадлежит [transport.go](transport.go), а
низкоуровневый путь — [u_transport.go](../u_transport.go). Значение `Dial == nil`
использует обычный dial-путь транспорта и само по себе не подключает parrot.

Владелец приложения закрывает тело HTTP-ответа и HTTP/3-транспорт. Если callback
создаёт отдельный `UTransport` или UDP-сокет, приложение также определяет их
время жизни и очистку при ошибках. Закрытие HTTP/3-транспорта нельзя считать
автоматическим освобождением всех внешних ресурсов callback.

[Сетевой пример](../example/uquic/main.go) — диагностический: он делает внешний
запрос и сохраняет TLS-ключи в `keylog.txt` через `KeyLogWriter`. Не используйте
его как production-шаблон и не публикуйте этот файл. Пример не является
проверкой полноты очистки ресурсов. Для первого сценария без сети используйте
[пример получения спецификации](../example_documentation_test.go).

[HTTP/3, RFC 9114](https://www.rfc-editor.org/rfc/rfc9114),
[QPACK, RFC 9204](https://www.rfc-editor.org/rfc/rfc9204) и
[HTTP Datagrams, RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) задают
протокольные источники. Их перечисление не является сертификатом полного
соответствия каждой возможности этого форка.

[Документация quic-go](https://quic-go.net/docs/) относится к upstream и его
версии API. Она полезна для объяснения устройства, но не заменяет справку
собранного checkout и проверки совместимости адаптеров этого форка.
