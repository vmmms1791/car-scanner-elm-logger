"""
Логер запросов Car Scanner: притворяется Wi-Fi адаптером ELM327 и записывает
все команды приложения. Автомобиль и VNCI НЕ нужны.

Запуск:   python elm_logger.py
В Car Scanner: Адаптер -> Wi-Fi -> IP ноутбука (скрипт покажет), порт 35000.
Остановка: Ctrl+C. Журнал дописывается в elm_log.txt.

Отладка сырого TCP-потока: set ELM_RAW=1 (Windows) / ELM_RAW=1 python ... (Linux).
Свои значения DID: положите рядом did_values.json вида {"F508": "01020304"}
(данные БЕЗ "62" и самого DID) - логер будет отвечать ими.
"""
import json
import os
import re
import socket
import threading
import time

PORT = 35000
RAW_DEBUG = os.environ.get("ELM_RAW") == "1"
LOG = open("elm_log.txt", "a", encoding="utf-8")
seen = {}            # нормализованная команда -> сколько раз
unknown_at = set()   # неизвестные AT-команды (логируем один раз)
lock = threading.Lock()

try:
    with open("did_values.json", encoding="utf-8") as f:
        DID_VALUES = {k.upper(): v.upper() for k, v in json.load(f).items()}
except (OSError, ValueError):
    DID_VALUES = {}


def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    with lock:
        print(line)
        LOG.write(line + "\n")
        LOG.flush()


def local_ips():
    ips = set()
    try:
        ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    for target in ("172.20.10.1", "192.168.0.1", "192.168.137.2", "8.8.8.8"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target, 80))
            ips.add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    return sorted(i for i in ips if not i.startswith(("127.", "169.254.")))


def describe(ip):
    if ip.startswith("172.20.10."):
        return "сеть точки доступа iPhone  <-- ЭТОТ АДРЕС ВВОДИТЕ В Car Scanner"
    if ip.startswith("192.168.137."):
        return "Мобильный хот-спот Windows"
    if ip.startswith("10."):
        return "похоже на VPN (например AmneziaVPN), не подходит"
    if ip.startswith("192.168."):
        return "домашняя сеть (роутер)"
    return ""


# ---------- данные ответов (только полезные байты, без "41" и номера PID) ----------
PID_DATA = {
    "00": "FFFFFFFF", "20": "FFFFFFFF", "40": "00000000", "60": "00000000",
    "01": "00000000",   # статус мониторов
    "03": "0000",       # состояние топливной системы
    "04": "64",         # нагрузка 39%
    "05": "5A",         # ОЖ: 0x5A-40 = 50 C
    "06": "80", "07": "80", "08": "80", "09": "80",   # топливные коррекции 0%
    "0A": "00", "0B": "64",
    "0C": "1AF8",       # обороты: 0x1AF8/4 = 1726 об/мин
    "0D": "3C",         # скорость 60 км/ч
    "0F": "3C",         # воздух на впуске 20 C
    "10": "0080",       # MAF 1.28 г/с
    "11": "4E",         # дроссель 30%
    "16": "8000", "17": "8000",
    "18": "00", "19": "00", "1A": "00", "1B": "00",
    "1C": "08", "1E": "00", "1F": "8000",
    "21": "0000", "24": "80008000", "2F": "80",
    "30": "00", "31": "8000", "33": "65",
    "42": "2EE0",       # 12.0 В
    "46": "3C",
}
VIN = "ELMLOGGER00000000".encode().hex().upper()     # ровно 17 символов
MODE09 = {
    "00": "50400000",                 # поддерживаются 02, 04, 0A
    "02": "01" + VIN,
    "04": "01" + "312E302E30".ljust(32, "0"),
    "0A": "01" + "00" * 16,
}


# ---------- состояние адаптера ----------
def new_state():
    return {"echo": True, "headers": False, "sh": "7DF", "cra": None,
            "caf": True, "auto": True, "proto": "6"}


def response_id(state):
    """CAN-ID, с которого 'отвечает' блок: берём из ATCRA, иначе выводим из ATSH."""
    if state["cra"]:
        return state["cra"]
    sh = state["sh"]
    if sh == "7DF":
        return "7E8"
    if len(sh) == 3 and sh.startswith("7E"):
        return f"7E{(int(sh[2], 16) + 8) & 0xF:X}"
    if sh == "710":                      # шлюз VW
        return "77A"
    return "7E8"


def fmt(data_hex, state):
    """Оформляет ответ как ELM327: с заголовками (ATH1) или без (ATH0), в т.ч. многокадровый."""
    n = len(data_hex) // 2
    if state["headers"]:
        rid = response_id(state)
        if n <= 7:
            return f"{rid}{n:02X}{data_hex}"
        lines = [f"{rid}10{n:02X}{data_hex[:12]}"]
        rest, sn = data_hex[12:], 1
        for i in range(0, len(rest), 14):
            lines.append(f"{rid}2{sn & 0xF:X}{rest[i:i + 14]}")
            sn += 1
        return "\r".join(lines)
    if n <= 7:
        return data_hex
    chunks = [data_hex[:12]] + [data_hex[i:i + 14] for i in range(12, len(data_hex), 14)]
    return "\r".join([f"{n:03X}"] + [f"{i}:{c}" for i, c in enumerate(chunks)])


def normalize(cmd):
    """Убирает пробелы и суффикс 'число ответов' (010D1 -> 010D), который ELM327 допускает."""
    c = cmd.replace(" ", "").upper()
    if (c and not c.startswith(("AT", "ST", "VT"))
            and re.fullmatch(r"[0-9A-F]+", c) and len(c) % 2 == 1):
        c = c[:-1]
    return c


# ---------- AT-команды ----------
OK_PREFIXES = ("ATL", "ATS", "ATM", "ATAT", "ATFC", "ATFI", "ATFT", "ATCP", "ATCM",
               "ATCEA", "ATV", "ATPB", "ATAL", "ATBI", "ATCV")


def at_command(c, state):
    if c.startswith("ATZ"):
        state.update(new_state())
        return "ELM327 v1.5"
    if c.startswith("ATI"):
        return "ELM327 v1.5"
    if c.startswith("AT@1"):
        return "OBDII to RS232 Interpreter"
    if c.startswith("ATE"):
        state["echo"] = c.endswith("1")
        return "OK"
    if c.startswith("ATH"):
        state["headers"] = c.endswith("1")
        return "OK"
    if c.startswith("ATRV"):
        return "12.4V"
    if c.startswith("ATDPN"):
        return ("A" if state["auto"] else "") + state["proto"]
    if c.startswith("ATDP"):
        return "ISO 15765-4 (CAN 11/500)"
    if c.startswith("ATSP"):
        arg = c[4:].lstrip("A")
        if arg in ("", "0"):
            state["auto"] = True
        else:
            state["auto"], state["proto"] = False, arg[0]
        return "OK"
    if c.startswith("ATSH"):
        state["sh"] = c[4:]
        return "OK"
    if c.startswith("ATCRA"):
        state["cra"] = c[5:] or None
        return "OK"
    if c.startswith("ATAR"):
        state["cra"] = None
        return "OK"
    if c.startswith("ATCAF"):
        state["caf"] = c.endswith("1")
        return "OK"
    if not c.startswith(OK_PREFIXES) and c not in unknown_at:
        unknown_at.add(c)
        log(f"UNKNOWN AT: {c}")
    return "OK"


# ---------- основной разбор ----------
def answer(cmd, state):
    c = cmd.replace(" ", "").upper()
    if c == "":
        return ""                         # только prompt
    if c.startswith("AT"):
        return at_command(c, state)
    if c == "STI":
        return "STN1170 v3.2.0"
    if c == "VTI":
        return "12.4V"

    c = normalize(c)
    if not state["caf"]:                  # ATCAF0: сырые CAN-кадры (например TP 2.0)
        return "NO DATA"

    if c.startswith("22") and len(c) >= 6:                    # UDS ReadDataByIdentifier
        did = c[2:6]
        return fmt("62" + did + DID_VALUES.get(did, "00000000"), state)
    if c.startswith("10") and len(c) >= 4:                    # UDS DiagnosticSessionControl
        return fmt(f"50{c[2:4]}003201F4", state)
    if c.startswith("27") and len(c) >= 4:                    # UDS SecurityAccess
        return fmt(f"67{c[2:4]}00000000", state)
    if c.startswith("3E") and len(c) >= 4:                    # TesterPresent
        return fmt(f"7E{c[2:4]}", state)
    if c.startswith("1902") and len(c) >= 6:                  # UDS ReadDTC: DTC нет
        return fmt("5902FF", state)

    if c.startswith("01") and len(c) >= 4:                    # Mode 01, до 6 PID за запрос
        pids = [c[i:i + 2] for i in range(2, len(c), 2)][:6]
        body = "".join(p + PID_DATA.get(p, "00000000") for p in pids)
        return fmt("41" + body, state)
    if c.startswith("02") and len(c) >= 4:
        return fmt(f"42{c[2:4]}00000000", state)
    if c == "03":
        return fmt("4300", state)
    if c == "04":
        return "44"
    if c == "07":
        return fmt("4700", state)
    if c == "0A":
        return fmt("4A00", state)
    if c.startswith("09") and len(c) >= 4:
        pid = c[2:4]
        if pid in MODE09:
            return fmt("49" + pid + MODE09[pid], state)
        return "NO DATA"
    return "NO DATA"


def handle(conn, addr):
    log(f"=== подключение от {addr[0]}:{addr[1]}")
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    state = new_state()
    buf = b""
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            if RAW_DEBUG:
                log(f"RAW RX: {data.hex()} | {data!r}")
            buf += data
            while b"\r" in buf:
                raw, buf = buf.split(b"\r", 1)
                cmd = raw.decode("ascii", errors="replace").strip()
                with lock:
                    key = normalize(cmd)
                    seen[key] = seen.get(key, 0) + 1
                resp = answer(cmd, state)
                if resp == "":
                    out = "\r>"
                else:
                    out = (cmd + "\r" if state["echo"] else "") + resp + "\r\r>"
                shown = resp.replace("\r", " | ") if resp else "(prompt only)"
                log(f"ПРИЛОЖЕНИЕ> {cmd!r:30}  ОТВЕТ: {shown}")
                time.sleep(0.01)
                conn.sendall(out.encode("ascii"))
    except OSError as e:
        log(f"ошибка соединения: {e}")
    finally:
        conn.close()
        log("=== соединение закрыто")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(5)
    log("=== запуск логера")
    print("Логер запущен. В Car Scanner: тип Wi-Fi, порт", PORT, "и IP ноутбука:")
    ips = local_ips()
    for ip in ips:
        print(f"    {ip:16} {describe(ip)}")
    if not any(ip.startswith("172.20.10.") for ip in ips):
        print("\n    Адреса 172.20.10.x нет: ноутбук не подключён к точке доступа iPhone?")
    print("Остановка: Ctrl+C\n")

    def hint():
        time.sleep(60)
        if not seen:
            print("\nПОДСКАЗКА: за минуту ни одной команды. Проверьте:")
            print("  1) Брандмауэр Windows (cmd от администратора):")
            print('     netsh advfirewall firewall add rule name="ELM logger" dir=in action=allow protocol=TCP localport=35000 profile=any')
            print("  2) iPhone: Настройки -> Конфиденциальность -> Локальная сеть -> разрешите Car Scanner.")
            print("  3) Отключите VPN на ноутбуке.")
            print("  4) Или подключите оба устройства к домашнему роутеру.\n")
    threading.Thread(target=hint, daemon=True).start()
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nУникальные команды приложения (количество):")
        for k, v in sorted(seen.items(), key=lambda kv: -kv[1]):
            print(f"  {k!r}: {v}")
            LOG.write(f"UNIQUE {k!r}: {v}\n")
        LOG.flush()


if __name__ == "__main__":
    main()
