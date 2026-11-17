# Как проверить checkout

Из корня репозитория используйте версию Go, совместимую с [go.mod](../../go.mod).

## Проверить одно свойство

Для теста пакета добавьте функцию вида `func TestName(t *testing.T)` в файл `*_test.go`
рядом с кодом. Случаи одного контракта можно именовать через `t.Run`.
Например, [тест чтения QUIC varint](../../quicvarint/varint_test.go)
проверяет, что `Parse` возвращает `io.ErrUnexpectedEOF`, когда байтов меньше заявленной длины.

```sh
go test -list '^TestParsing' ./quicvarint
go test -count=1 -v -run '^TestParsingFailures$/^slice_too_short$' ./quicvarint
```

Первая команда показывает функции верхнего уровня. Во второй строка
`--- PASS: TestParsingFailures/slice_too_short` подтверждает выполнение
конкретного случая. Go может вернуть `ok` и при пустом выборе по `-run`.
Для всех случаев пакета выполните `go test -count=1 ./quicvarint`.

## Проверить checkout целиком

Сначала проверьте сборку и локальный CI-контракт:

```sh
go build ./...
go test -count=1 ./.ci
```

Затем запустите тесты пакетов:

```sh
go test -count=1 ./...
```

Последняя команда включает пакеты с зависимостью от ОС, сети и таймингов. Её
успех не заменяет удалённую матрицу и race/integration варианты.

Состав матриц и смысл обязательного результата описаны в
[справке CI](../reference/ci-checks.md). Команды заданы в workflow-файлах.

- [Go Build](../../.github/workflows/go_build.yml);
- [unit-проверки](../../.github/workflows/ginkgo_test.yml);
- [integration](../../.github/workflows/integration.yml).

Для изменения, которое должно попасть в `main`, проверяйте обязательный итоговый
CI на актуальном SHA/merge candidate. Повтор отдельного случайно нестабильного job
не является исправлением воспроизводимого дефекта race detector.
