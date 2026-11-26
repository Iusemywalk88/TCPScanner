![CI](https://github.com/Iusemywalk88/TCPScanner/actions/workflows/ci.yml/badge.svg)

# TCPScanner

Пакет `portscan` выполняет TCP Connect-сканирование портов на одном или нескольких
хостах и пригоден для встраивания в другие Go-приложения.

Пакет **делает**:

- проверку доступности TCP-портов по одному или нескольким хостам;
- поддержку IPv4, IPv6 (включая адреса с зоной) и DNS-имён;
- списки портов, диапазоны и их объединение;
- конкурентное выполнение проверок с настраиваемым лимитом;
- отмену через `context.Context`.

Пакет **не делает**:

- SYN-сканирование, UDP-сканирование, работу с raw sockets;
- определение операционной системы, обход межсетевых экранов;
- эксплуатацию уязвимостей;
- полноценный аналог Nmap.

## Установка

```bash
go get github.com/Iusemywalk88/TCPScanner/portscan
```

Требуется Go 1.25.5.

## Быстрый старт

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Iusemywalk88/TCPScanner/portscan"
)

func main() {
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		fmt.Println("scanner:", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"192.168.1.10", "192.168.1.11"},
		portscan.Range(1, 1000),
	)
	if err != nil {
		switch {
		case errors.Is(err, portscan.ErrInvalidPort):
			fmt.Println("invalid port specification:", err)
		case errors.Is(err, portscan.ErrInvalidTarget):
			fmt.Println("invalid target:", err)
		default:
			fmt.Println("scan:", err)
		}
		return
	}

	for result := range results {
		fmt.Printf("%s:%d %s\n", result.Host, result.Port, result.State)
	}

	if err := ctx.Err(); err != nil {
		fmt.Println("scan stopped early:", err)
	}
}
```

## Публичный API

### Сканнер

| Сущность | Назначение |
|---|---|
| `Scanner` | Неизменяемый после `New` сканнер; безопасен для конкурентного использования. |
| `New(opts ...Option) (*Scanner, error)` | Создаёт сканнер; все невалидные опции собираются в одну ошибку через `errors.Join`. |
| `(*Scanner).Scan(ctx, hosts, ports) (<-chan Result, error)` | Запускает сканирование и возвращает канал результатов. |

### Опции

| Опция | Значение по умолчанию | Допустимый диапазон |
|---|---|---|
| `WithConcurrency(n int)` | 100 | от 1 до 65535 |
| `WithConnectTimeout(d time.Duration)` | 1s | больше 0 |
| `WithDialer(d Dialer)` | `&net.Dialer{}` | не `nil` |
| `WithResolver(r Resolver)` | `net.DefaultResolver` | не `nil` |

Невалидное значение опции делает `New` ошибочным: возвращается ошибка, оборачивающая
`ErrInvalidOption`; все найденные проблемы собираются вместе.

### Порты

| Функция | Назначение |
|---|---|
| `Range(from, to int) PortSpec` | Инклюзивный диапазон `[from, to]`. |
| `Ports(ports ...int) PortSpec` | Список отдельных портов. |
| `Union(specs ...PortSpec) PortSpec` | Объединение диапазонов и отдельных портов. |

Конструкторы ошибок не возвращают: невалидные значения запоминаются внутри `PortSpec`,
а ошибку валидации возвращает `Scan` (оборачивает `ErrInvalidPort`). Дубликаты и
пересечения портов сворачиваются, результат сортируется по возрастанию.

### Результат

| Поле | Назначение |
|---|---|
| `Host string` | Хост ровно в том виде, как передан в `Scan`. |
| `IP netip.Addr` | Адрес, к которому выполнялось подключение; нулевой при ошибке резолва. |
| `Port uint16` | Проверяемый TCP-порт; 0 при ошибке резолва. |
| `State State` | Состояние порта. |
| `Duration time.Duration` | Время, затраченное на проверку. |
| `Err error` | Исходная ошибка; равен `nil` только при `State == StateOpen`. |

Состояния (`State`): `StateOpen` («open»), `StateClosed` («closed»),
`StateTimeout` («timeout»), `StateUnreachable` («unreachable»),
`StateCanceled` («canceled»), `StateError` («error»). Нулевое значение `State`
невалидно, его `String()` возвращает «invalid».

### Ошибки

| Ошибка | Когда возникает | Где искать |
|---|---|---|
| `ErrInvalidTarget` | Пустой или синтаксически некорректный хост; пустой список хостов. | Ошибка `Scan` |
| `ErrInvalidPort` | Порт 0, порт больше 65535, обратный диапазон, пустой список портов. | Ошибка `Scan` |
| `ErrInvalidOption` | Невалидная опция в `New`; нулевой `Scanner` в `Scan`. | Ошибка `New` / `Scan` |
| `ErrResolve` | Неразрешимое DNS-имя. | `Result.Err` |

### Интерфейсы Dialer и Resolver

| Интерфейс | Зачем экспортирован |
|---|---|
| `Dialer` (метод `DialContext`) | Чтобы в тестах и в приложениях подменять сетевой стек через `WithDialer`. |
| `Resolver` (метод `LookupNetIP`) | Чтобы подменять резолвинг DNS через `WithResolver`. |

## Поведение в крайних случаях

| Ситуация | Поведение |
|---|---|
| Пустой хост | `Scan` возвращает ошибку, оборачивающую `ErrInvalidTarget`. |
| Некорректный адрес | `Scan` возвращает ошибку, оборачивающую `ErrInvalidTarget`. |
| Хост из цифр и точек, не являющийся корректным IP | `Scan` возвращает ошибку, оборачивающую `ErrInvalidTarget`. |
| Неразрешимое DNS-имя | Один `Result` на хост: `State=StateError`, `Port=0`, нулевой `IP`, `Err` оборачивает `ErrResolve`; остальные хосты продолжают сканироваться. |
| Повторяющиеся цели | Дедупликация по нормализованному виду; побеждает первый в списке. |
| Одно имя с несколькими IP | Сканируются все адреса. |
| Порт 0 | `Scan` возвращает ошибку, оборачивающую `ErrInvalidPort`. |
| Порт больше 65535 | `Scan` возвращает ошибку, оборачивающую `ErrInvalidPort`. |
| Обратный диапазон (например 1000–1) | `Scan` возвращает ошибку, оборачивающую `ErrInvalidPort`. |
| Дубликаты и пересечения портов | Сворачиваются, результат по возрастанию без дубликатов. |
| Пустой список портов | `Scan` возвращает ошибку, оборачивающую `ErrInvalidPort`. |
| Пустой список хостов | `Scan` возвращает ошибку, оборачивающую `ErrInvalidTarget`. |
| Отменённый `ctx` | При валидном вводе `Scan` возвращает `ctx.Err()`; при невалидном вводе — ошибку валидации. |
| Нулевой `Scanner` (без `New`) | `Scan` возвращает ошибку, оборачивающую `ErrInvalidOption`, без паники. |

## Конкурентность и отмена

- Канал результатов нужно либо вычитать до закрытия, либо отменить `ctx`; иначе
  горутины сканирования не завершатся.
- Медленный читатель: отправка результата блокирует воркер (backpressure), поэтому
  результаты не теряются.
- При отмене: новые задания не стартуют, начатые подключения прерываются и дают
  `StateCanceled`, неначатые задания результата не получают.
- Причину досрочного завершения после закрытия канала можно узнать через
  `ctx.Err()`.
- Порядок результатов не определён.
- Лимит `concurrency` действует на один вызов `Scan`.

## Как определяется состояние порта

Состояние определяется только через `errors.Is` / `errors.As` и метод
`net.Error.Timeout()`, без разбора текста ошибки. Порядок проверок:

| № | Условие | Состояние |
|---|---|---|
| 1 | `err == nil` | `open` |
| 2 | `ctx.Err() != nil` (родительский) | `canceled` |
| 3 | `errors.Is(err, syscall.ECONNREFUSED)` | `closed` |
| 4 | `errors.Is(err, syscall.ENETUNREACH)` или `errors.Is(err, syscall.EHOSTUNREACH)` | `unreachable` |
| 5 | `net.Error` с `Timeout() == true` | `timeout` |
| 6 | иначе | `error` |

Родительский `ctx` проверяется раньше ошибки: и отмена пользователя, и наш таймаут
попытки приходят как `context.DeadlineExceeded`, и только `ctx.Err()` родителя
позволяет отличить отмену от таймаута.

## Тестирование

`Dialer` и `Resolver` можно подменять через `WithDialer` и `WithResolver`:

```go
scanner, _ := portscan.New(
    portscan.WithDialer(myDialer),
    portscan.WithResolver(myResolver),
)
```

Полный прогон тестов:

```bash
go test -race ./...
```

## Ограничения

- Рассчитан на Linux и macOS. На Windows коды ошибок ядра другие, поэтому
  классификация `closed`/`unreachable` не гарантирована; пакет при этом собирается.
- Хосты резолвятся последовательно и сканируются по очереди, поэтому при большом
  `concurrency` одна цель получает до N одновременных подключений.
- Резолв DNS выполняется последовательно в одной горутине и ограничен только
  контекстом и собственными таймаутами резолвера (`WithConnectTimeout` на него не
  действует); зависший резолв одного имени задерживает сканирование всех следующих
  целей, пока он не завершится или `ctx` не будет отменён.
- Хост из цифр и точек, не являющийся корректным IP-адресом, отклоняется с
  `ErrInvalidTarget` (устаревшие формы `inet_aton` не поддерживаются; по RFC 3696
  последняя метка имени не может быть целиком числовой).
- CIDR не поддерживается.
- Международные доменные имена (IDN) нужно передавать в punycode.
- Верхний предел `concurrency` — 65535.

## Зависимости

Зависимостей нет — используется только стандартная библиотека Go (`net`,
`net/netip`, `context`, `sync`, `syscall`). Для TCP Connect-сканирования их
возможностей достаточно, сторонние библиотеки для задачи не требуются.
