# Car Scanner ELM327 Logger

Эмулятор Wi-Fi ELM327 адаптера для перехвата и логирования команд приложения **Car Scanner** (iOS/Android).

## Назначение

- Притворяется ELM327 Wi-Fi адаптером на порту 35000
- Логирует все AT-команды и OBD/UDS запросы от Car Scanner
- Поддерживает VW MEB (ID.7, ID.4, ID.5) — UDS over ISO-TP
- Сохраняет журнал в `elm_log.txt`

## Файлы

| Файл | Описание |
|------|----------|
| `elm_logger.py` | Основной скрипт эмулятора |
| `car_scanner_protocol.json` | Разобранный протокол Car Scanner (381 уникальная команда) |

## Быстрый старт

```bash
# Запуск
python elm_logger.py

# В Car Scanner: Настройки → Адаптер → Wi-Fi → IP ноутбука:35000
# Журнал: elm_log.txt
```

## Требования

- Python 3.7+
- Порт 35000 открыт в фаерволе
- На iPhone: Настройки → Конфиденциальность → Локальная сеть → Car Scanner = ВКЛ

## Поддерживаемые протоколы

- **AT-команды**: ATZ, ATE0, ATH1, ATSP0/6/B, ATSH, ATFCSM, ATFCSD, ATCRA, ATAR, ATST, ATCAF, ATCEA
- **OBD Mode 01**: Composite PID запросы (010103040A0B0D), single PID (010C, 010D, 0105...)
- **OBD Mode 06**: 247 MID (readiness monitors)
- **OBD Mode 09**: VIN (0902), CalID (0904), ECU Name (090A)
- **UDS 0x10**: Session Control (10011, 10031)
- **UDS 0x19**: Read DTC (190208, 1902AE, 1902AF, 19C000100003011)
- **UDS 0x1A**: Read DTC by status (1A90, 1A91, 1A9A, 1A9B)
- **UDS 0x22**: ReadDataByIdentifier (47 DIDs: F1xx, F5xx, 2Axx, 3Cxx, 04A3, 0600)

## Результаты анализа (car_scanner_protocol.json)

- **5646 команд** в логе, **381 уникальных**
- **UDS DIDs**: 47 шт. (VW MEB variant coding, equipment, component protection)
- **Mode 06**: 247 MID (полный набор OBD monitors)
- **Composite PID**: Car Scanner запрашивает батчами (010103040A0B0D, 01030D101124)
- **ISO-TP handshake**: ATAR → ATSH7DF → ATFCSM1 → ATFCSD300000 → ATCRA77A → ATSP6

## Лицензия

MIT
