# uQUIC — форк Labpics

Go-библиотека для настройки QUIC Initial и TLS ClientHello. Репозиторий является
форком [uQUIC](https://github.com/refraction-networking/uquic), основанного на
[quic-go](https://github.com/quic-go/quic-go). У модуля сохранён upstream module
path `github.com/refraction-networking/uquic`; сам module path не выбирает этот
форк автоматически.

Проект остаётся исследовательским. Настройка отпечатка не доказывает
неотличимость от браузера, безопасность канала или доступность в заданной сети.

## Начать

[Первый сценарий без внешней сети](docs/tutorial/first-profile.md) показывает,
как получить выбранный профиль и проверить, что он разрешается в `QUICSpec`.
Он использует исполняемый Go Example, а не копию API в Markdown.

Полная документация разделена по назначению в [индексе](docs/README.md):
обучение, практические инструкции, справка и объяснения.

## Проверка и безопасность

[Как проверить checkout](docs/how-to/verify-checkout.md) описывает локальные
команды и границы их доказательства. Уязвимости форка сообщаются по
[приватному каналу Labpics](SECURITY.md).

[Границы гарантий](docs/explanation/guarantees.md) отдельно объясняют, чего не
доказывают fingerprint- и integration-тесты.

[Лицензия и upstream-атрибуция](LICENSE).
