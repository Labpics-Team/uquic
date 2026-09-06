# Документация uQUIC

Страницы разделены по задаче читателя. Индекс не является доказательством
полноты API: точные сигнатуры принадлежат исходникам и `go doc`.

## Обучение

- [Первый профиль без внешней сети](tutorial/first-profile.md) — короткий путь от
  checkout до работающего `QUICSpec`.

## Практические инструкции

- [Проверить checkout](how-to/verify-checkout.md).
- [Обновить сохранённый браузерный эталон](how-to/update-browser-profile.md).
- [Запустить локальный стенд метрик](../metrics/dashboards/README.md).
- [Сообщить об уязвимости](../SECURITY.md).

## Справка

- [Контракт выбора браузерного профиля](reference/browser-profile.md).
- [HTTP/3 transport](../http3/README.md).
- [Внутренний двусвязный список](../internal/utils/linkedlist/README.md).
- [Происхождение upstream-версии](../Changelog.md).

## Объяснения

- [Что доказывает сохранённый browser evidence](explanation/browser-evidence.md).
- [Граница интеграции Ametyst](explanation/integration-boundary.md).
- [Границы гарантий](explanation/guarantees.md).

Старый смешанный документ `docs/ametyst-integration.md` сохранён только как
redirect к этим страницам, чтобы существующие ссылки не становились битым путём.
