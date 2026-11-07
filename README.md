# Car Scanner ELM327 Logger

Эмулятор Wi-Fi ELM327 адаптера для перехвата и логирования команд приложения **Car Scanner** (iOS/Android) с поддержкой **VW MEB (ID.3, ID.4, ID.5, ID.7, Enyaq, Q4 e-tron)**.

## Назначение

- Притворяется ELM327 Wi-Fi адаптером на порту 35000
- Логирует все AT-команды и OBD/UDS запросы от Car Scanner
- Поддерживает **ISO-TP multi-frame**, **composite PID**, **UDS 0x10/0x19/0x22/0x27/0x3E**
- Внешняя конфигурация DID через `did_values.json`
- Сохраняет журнал в `elm_log.txt`

## Файлы

| Файл | Описание |
|------|----------|
| `elm_logger.py` | Основной эмулятор (ISO-TP, composite PID, UDS, AT state machine) |
| `parse_elm_log.py` | Парсер лога: multiple connections, adapter context, polling stats |
| `did_values.json.example` | Пример конфига DID (скопируйте в `did_values.json` и редактируйте) |
| `car_scanner_protocol.json` | Базовый разобранный протокол (381 уникальная команда) |
| `car_scanner_protocol_full.json` | Полный разбор с polling, contexts, per-connection stats |

## Быстрый старт

```bash
# 1. (Опционально) Создайте did_values.json из примера
cp did_values.json.example did_values.json
# Отредактируйте значения под ваш автомобиль

# 2. Запуск
python elm_logger.py

# 3. В Car Scanner: Настройки → Адаптер → Wi-Fi → IP ноутбука:35000
# Журнал: elm_log.txt
```

## Парсинг лога

```bash
python parse_elm_log.py elm_log.txt car_scanner_protocol_parsed.json
```

Выдаст:
- Статистику по подключениям
- Категории команд (adapter_setup, obd_mode_XX, uds_XX, raw_can_frames)
- Циклический опрос с периодом
- UDS 0x22 DIDs с контекстами (SH/CRA)

## Поддерживаемые протоколы

### AT-команды (state machine)
- `ATZ` / `ATI` — reset / info
- `ATE0/1` — echo off/on
- `ATH0/1` — headers off/on
- `ATRV` — voltage
- `ATDPN` / `ATDP` — protocol name/description
- `ATSP0/6/B` — set protocol (auto / ISO-TP / user)
- `ATSH` — set TX header (7DF, 710, 200...)
- `ATCRA` — set RX address (77A for VW gateway)
- `ATAR` — adapter reset (clears CRA)
- `ATCAF0/1` — CAN formatting off/on (raw CAN frames)
- `ATFCSM`, `ATFCSD`, `ATFCSH`, `ATFT`, `ATFI` — flow control
- `ATST` — timing (P2, P2*, P3)

### OBD Mode 01 (Composite PID — до 6 в одном запросе)
`010103040A0B0D` = Mode 01 + PIDs [01,03,04,0A,0B,0D]

### UDS Services
| Service | Request | Response | Purpose |
|---------|---------|----------|---------|
| 0x10 | `1001` / `1003` | `5001003201F4` / `5003...` | Session Control (default/extended) |
| 0x19 | `190208`, `1902AE`, `1902AF` | `5902FF` | Read DTC (no DTCs) |
| 0x22 | `22xxxx` | `62xxxx + data` | ReadDataByIdentifier |
| 0x27 | `27xx` | `67xx00000000` | Security Access (seed) |
| 0x3E | `3Exx` | `7Exx` | Tester Present |

### Важные UDS DIDs (0x22) для VW MEB
- **F17B–F1A9** (26+ DIDs): Variant coding, adaptation, SW version, calibration
- **F500, F508, F50F, F517, F518, F51E**: Vehicle configuration / equipment codes
- **2A26, 2A28, 2A2A, 2A2F**: Component protection / immobilizer
- **3C00**: OBD monitor status
- **04A3**: VIN / vehicle identification
- **0600**: ECU identification / part number

### ISO-TP Parameters (from AT commands)
| Parameter | Value | AT Command |
|-----------|-------|------------|
| TX Header (functional) | 7DF | `ATSH7DF` |
| TX Header (physical GW) | 710 | `ATSH710` |
| TX Header (other ECU) | 200 | `ATSH200` |
| RX Address (physical GW) | 77A | `ATCRA77A` |
| Block Size (BS) | 0 | `ATFCSD300000` |
| STmin | 0 | `ATFCSD300000` |
| Flow Control | Enabled | `ATFCSM1` |
| Protocol | 6 (ISO-TP) | `ATSP6` |

## Настройка DID значений

Создайте `did_values.json` рядом со скриптом:
```json
{
  "F17B": "01020304",
  "F508": "00000000",
  "2A26": "00000000"
}
```
Формат: **только данные** (БЕЗ `62` и самого DID), 4+ байт в hex.

## Отладка сырого TCP

```bash
# Linux
ELM_RAW=1 python elm_logger.py

# Windows PowerShell
$env:ELM_RAW=1; python elm_logger.py
```

## Требования

- Python 3.7+
- Порт 35000 открыт в фаерволе (`netsh advfirewall firewall add rule name="ELM logger" dir=in action=allow protocol=TCP localport=35000 profile=any`)
- iPhone: Настройки → Конфиденциальность → Локальная сеть → Car Scanner = ВКЛ

## Результаты анализа (car_scanner_protocol_full.json)

- **2 подключения**: 5646 + 4995 команд
- **Polling**: `010D` (4615×, 40мс), `22F508`/`22F50F` (86×, 0.89с), `22F517`/`22F518`/`22F51E` (84×, 0.15с), `0118`–`011B` (62×, 0.23с)
- **UDS 0x22 DIDs**: 70+ (F1xx, F5xx, 2Axx, 3C00, 04A3, 0600)
- **AT contexts**: `SH=7DF CRA=-` (функционал) vs `SH=710 CRA=77A` (физический шлюз)
- **Raw CAN frames**: `19C00010000301`, `1FC00010000301` (с `SH=200`)

## Лицензия

MIT
