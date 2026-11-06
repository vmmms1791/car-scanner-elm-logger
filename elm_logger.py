"""
Логер запросов Car Scanner: притворяется Wi-Fi адаптером ELM327 и записывает
все команды, которые присылает приложение. Автомобиль и VNCI НЕ нужны.

Сценарий: ноутбук подключён к точке доступа iPhone (Режим модема), Car Scanner
запущен на этом же iPhone.

Запуск (на ноутбуке):   python elm_logger.py
Потом в Car Scanner: Настройки -> Адаптер -> тип Wi-Fi -> IP ноутбука, порт 35000
(скрипт сам покажет, какой IP вводить). Нажмите "Подключиться".
Остановка: Ctrl+C. Журнал сохраняется в elm_log.txt.

Скрипт отвечает на AT-команды как ELM327, на запросы данных отвечает NO DATA.
Если приложение остановится рано, это тоже полезный результат.
"""
import socket
import sys
import threading
import time

PORT = 35000
LOG = open("elm_log.txt", "a", encoding="utf-8")
seen = {}
lock = threading.Lock()


def log(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    with lock:
        print(line)
        LOG.write(line + "\n")
        LOG.flush()


def local_ips():
    """Находит IPv4-адреса ноутбука. Адрес, через который виден шлюз iPhone, определяется точно."""
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
    if ip.startswith("10.8.") or ip.startswith("10."):
        return "похоже на VPN (например AmneziaVPN), не подходит"
    if ip.startswith("192.168."):
        return "домашняя сеть (роутер)"
    return ""


# PID responses WITHOUT spaces (real ELM327 format) - DATA ONLY (without headers)
PID_DATA = {
    # Mode 01: Current Data - PID support
    "00": "4100FFFFFFFF",           # PIDs 01-20 supported (6 bytes)
    "20": "4120FFFFFFFF",           # PIDs 21-40 supported (6 bytes)
    "40": "414000000000",           # PIDs 41-60 (6 bytes)
    "60": "416000000000",           # PIDs 61-80 (6 bytes)
    
    # Common PIDs - format: 41 + PID + data bytes (no spaces)
    "04": "410464",                 # Calculated Load: 39%
    "05": "41055A",                 # Coolant Temp: 90°C
    "0C": "410C1AF8",               # RPM: 6904
    "0D": "410D3C",                 # Vehicle Speed: 60 km/h
    "0F": "410F3C",                 # Intake Air Temp
    "10": "41100080",               # MAF Flow
    "11": "41114E",                 # Throttle Position: 30%
    "1C": "411C08",                 # OBD Standards
    "1F": "411F8000",               # Run Time
    "30": "413000000000",           # Warm-ups since DTC clear
    "31": "41318000",               # Distance since DTC clear
    "42": "41422EE0",               # Control Module Voltage: 12.0V
    "46": "41465A",                 # Ambient Air Temp
    
    # Mode 09: Vehicle Info
    "0902": "4902015846313233343536373839303132330000",  # VIN
    "0904": "490401312E302E30000000000000000000000000",  # Calibration ID
    "090A": "490A00000000000000000000000000000000",      # ECU Name
}


# UDS 0x22 (ReadDataByIdentifier) responses for VW MEB
# Format: 62 + DID (4 hex chars) + data bytes
UDS_DID_RESPONSES = {
    # Common VW MEB DIDs
    "1E3B": "621E3B01020304",       # Example data
    "1E3D": "621E3D05060708",
    "1E0E": "621E0E11223344",
    "1E0F": "621E0F55667788",
    "1E1B": "621E1B99AABBCC",
    "1E1C": "621E1CDDEEFF00",
    "1EAE": "621EAE11223344",
    "1EAF": "621EAF55667788",
    "1EB0": "621EB099AABBCC",
    "1EB1": "621EB1DDEEFF00",
    "1EB2": "621EB211223344",
    "1EB3": "621EB355667788",
    "1EB4": "621EB499AABBCC",
    "1EB5": "621EB5DDEEFF00",
    "1EB6": "621EB611223344",
    "1EB7": "621EB755667788",
    "1EB8": "621EB899AABBCC",
    "1EB9": "621EB9DDEEFF00",
    "1EBA": "621EBA11223344",
    "1EBB": "621EBB55667788",
    "1EBC": "621EBC99AABBCC",
    "1EBD": "621EBDDDEEFF00",
    "1E33": "621E3311223344",
    "1E34": "621E3455667788",
    "1E32": "621E3299AABBCC",
    "1E36": "621E36DDEEFF00",
    "1E38": "621E3811223344",
    "1E39": "621E3955667788",
    "1E2C": "621E2C99AABBCC",
    "1E2D": "621E2DDDEEFF00",
    "1E3C": "621E3C11223344",
    "1E40": "621E4055667788",
    "1E41": "621E4199AABBCC",
    "1E42": "621E42DDEEFF00",
    "1E43": "621E4311223344",
    "1E44": "621E4455667788",
    "1E45": "621E4599AABBCC",
    "1E46": "621E46DDEEFF00",
    "1E47": "621E4711223344",
    "1E48": "621E4855667788",
    "1E49": "621E4999AABBCC",
    "1E4A": "621E4ADDEEFF00",
    "1E4B": "621E4B11223344",
    "1E4C": "621E4C55667788",
    "1E4D": "621E4D99AABBCC",
    "1E4E": "621E4EDDEEFF00",
    "1E4F": "621E4F11223344",
    "1E50": "621E5055667788",
    "1E51": "621E5199AABBCC",
    "1E52": "621E52DDEEFF00",
    "1E53": "621E5311223344",
    "1E54": "621E5455667788",
    "1E55": "621E5599AABBCC",
    "1E56": "621E56DDEEFF00",
    "1E57": "621E5711223344",
    "1E58": "621E5855667788",
    "1E59": "621E5999AABBCC",
    "1E5A": "621E5ADDEEFF00",
    "1E5B": "621E5B11223344",
    "1E5C": "621E5C55667788",
    "1E5D": "621E5D99AABBCC",
    "1E5E": "621E5EDDEEFF00",
    "1E5F": "621E5F11223344",
    "1E60": "621E6055667788",
    "1E61": "621E6199AABBCC",
    "1E62": "621E62DDEEFF00",
    "1E63": "621E6311223344",
    "1E64": "621E6455667788",
    "1E65": "621E6599AABBCC",
    "1E66": "621E66DDEEFF00",
    "1E67": "621E6711223344",
    "1E68": "621E6855667788",
    "1E69": "621E6999AABBCC",
    "1E6A": "621E6ADDEEFF00",
    "1E6B": "621E6B11223344",
    "1E6C": "621E6C55667788",
    "1E6D": "621E6D99AABBCC",
    "1E6E": "621E6EDDEEFF00",
    "1E6F": "621E6F11223344",
    "1E70": "621E7055667788",
    "1E71": "621E7199AABBCC",
    "1E72": "621E72DDEEFF00",
    "1E73": "621E7311223344",
    "1E74": "621E7455667788",
    "1E75": "621E7599AABBCC",
    "1E76": "621E76DDEEFF00",
    "1E77": "621E7711223344",
    "1E78": "621E7855667788",
    "1E79": "621E7999AABBCC",
    "1E7A": "621E7ADDEEFF00",
    "1E7B": "621E7B11223344",
    "1E7C": "621E7C55667788",
    "1E7D": "621E7D99AABBCC",
    "1E7E": "621E7EDDEEFF00",
    "1E7F": "621E7F11223344",
    "1E80": "621E8055667788",
    "1E81": "621E8199AABBCC",
    "1E82": "621E82DDEEFF00",
    "1E83": "621E8311223344",
    "1E84": "621E8455667788",
    "1E85": "621E8599AABBCC",
    "1E86": "621E86DDEEFF00",
    "1E87": "621E8711223344",
    "1E88": "621E8855667788",
    "1E89": "621E8999AABBCC",
    "1E8A": "621E8ADDEEFF00",
    "1E8B": "621E8B11223344",
    "1E8C": "621E8C55667788",
    "1E8D": "621E8D99AABBCC",
    "1E8E": "621E8EDDEEFF00",
    "1E8F": "621E8F11223344",
    "1E90": "621E9055667788",
    "1E91": "621E9199AABBCC",
    "1E92": "621E92DDEEFF00",
    "1E93": "621E9311223344",
    "1E94": "621E9455667788",
    "1E95": "621E9599AABBCC",
    "1E96": "621E96DDEEFF00",
    "1E97": "621E9711223344",
    "1E98": "621E9855667788",
    "1E99": "621E9999AABBCC",
    "1E9A": "621E9ADDEEFF00",
    "1E9B": "621E9B11223344",
    "1E9C": "621E9C55667788",
    "1E9D": "621E9D99AABBCC",
    "1E9E": "621E9EDDEEFF00",
    "1E9F": "621E9F11223344",
    "1EA0": "621EA055667788",
    "1EA1": "621EA199AABBCC",
    "1EA2": "621EA2DDEEFF00",
    "1EA3": "621EA311223344",
    "1EA4": "621EA455667788",
    "1EA5": "621EA599AABBCC",
    "1EA6": "621EA6DDEEFF00",
    "1EA7": "621EA711223344",
    "1EA8": "621EA855667788",
    "1EA9": "621EA999AABBCC",
    "1EAA": "621EAADDEEFF00",
    "1EAB": "621EAB11223344",
    "1EAC": "621EAC55667788",
    "1EAD": "621EAD99AABBCC",
    "1EAE": "621EAEDDEEFF00",
    "1EAF": "621EAF11223344",
    
    # Other ranges seen in log
    "F500": "62F50001020304",
    "F40D": "62F40D05060708",
    "F40C": "62F40C11223344",
    "F449": "62F44955667788",
    "F817": "62F81799AABBCC",
    "7448": "62744811223344",
    "743B": "62743B55667788",
    "7425": "62742599AABBCC",
    "7426": "627426DDEEFF00",
    "7427": "62742711223344",
    "7428": "62742855667788",
    "7429": "62742999AABBCC",
    "742A": "62742ADDEEFF00",
    "742B": "62742B11223344",
    "742C": "62742C55667788",
    "710": "62071001020304",
    "713": "62071305060708",
    "744": "62074411223344",
    "746": "62074655667788",
    "767": "62076799AABBCC",
    "7DF": "6207DFDDEEFF00",
    "7B0": "6207B011223344",
    "7AE": "6207AE55667788",
    "7D1": "6207D199AABBCC",
    "77A": "62077ADDEEFF00",
    "77D": "62077D11223344",
    "2431": "62243155667788",
    "2603": "62260399AABBCC",
    "2604": "622604DDEEFF00",
    "2605": "62260511223344",
    "2607": "62260755667788",
    "2609": "62260999AABBCC",
    "260A": "62260ADDEEFF00",
    "260C": "62260C11223344",
    "260D": "62260D55667788",
    "2612": "62261299AABBCC",
    "2613": "622613DDEEFF00",
    "261E": "62261E11223344",
    "261F": "62261F55667788",
    "2620": "62262099AABBCC",
    "2621": "622621DDEEFF00",
    "2622": "62262211223344",
    "2626": "62262655667788",
    "263D": "62263D99AABBCC",
    "26ED": "6226EDDDEEFF00",
    "27C4": "6227C411223344",
    "276D": "62276D55667788",
    "29D4": "6229D499AABBCC",
    "295A": "62295ADDEEFF00",
    "2A0B": "622A0B11223344",
    "2A53": "622A5355667788",
    "2AB2": "622AB299AABBCC",
    "2AB4": "622AB4DDEEFF00",
    "2AB5": "622AB511223344",
    "2AB6": "622AB655667788",
    "2AB7": "622AB799AABBCC",
    "2AB8": "622AB8DDEEFF00",
    "2AF7": "622AF711223344",
    "1620": "62162055667788",
    "1621": "62162199AABBCC",
    "1622": "621622DDEEFF00",
    "1623": "62162311223344",
    "1624": "62162455667788",
    "189B": "62189B99AABBCC",
    "189D": "62189DDDEEFF00",
    "1DDA": "621DDA11223344",
    "1DA7": "621DA755667788",
    "1525": "62152599AABBCC",
    "15D1": "6215D1DDEEFF00",
    "1007": "62100711223344",
    "1008": "62100855667788",
    "1009": "62100999AABBCC",
    "100A": "62100ADDEEFF00",
    "103D": "62103D11223344",
    "103E": "62103E55667788",
    "1040": "62104099AABBCC",
    "1041": "621041DDEEFF00",
    "1042": "62104211223344",
    "028C": "62028C55667788",
    "02BD": "6202BD99AABBCC",
    "0308": "620308DDEEFF00",
    "0335": "62033511223344",
    "033B": "62033B55667788",
    "0343": "62034399AABBCC",
    "0344": "620344DDEEFF00",
    "0346": "62034611223344",
    "035E": "62035E55667788",
    "0360": "62036099AABBCC",
    "0364": "620364DDEEFF00",
    "0800": "62080011223344",
    "0805": "62080555667788",
    "0806": "62080699AABBCC",
    "086D": "62086DDDEEFF00",
    "1800": "62180055667788",
    "1801": "62180199AABBCC",
    "1802": "621802DDEEFF00",
    "1803": "62180311223344",
    "2005": "62200555667788",
    "2055": "62205599AABBCC",
    "2200": "622200DDEEFF00",
    "3DEF": "623DEF11223344",
    "3DF8": "623DF855667788",
    "3EE7": "623EE799AABBCC",
    "3EE8": "623EE8DDEEFF00",
    "3EE9": "623EE911223344",
    "3EEA": "623EEA55667788",
    "3EEB": "623EEB99AABBCC",
    "3EED": "623EEDDDEEFF00",
    "3E93": "623E9311223344",
    "3E98": "623E9855667788",
    "43B8": "6243B899AABBCC",
    "43B9": "6243B9DDEEFF00",
    "4539": "62453911223344",
    "4657": "62465755667788",
    "465B": "62465B99AABBCC",
    "465D": "62465DDDEEFF00",
    "4672": "62467211223344",
    "4675": "62467555667788",
    "40C8": "6240C899AABBCC",
    "4EEF": "624EEFDDEEFF00",
    "4FAE": "624FAE11223344",
    "5170": "62517055667788",
    "5171": "62517199AABBCC",
    "58E1": "6258E1DDEEFF00",
    "5867": "62586711223344",
    "2CCC": "622CCC55667788",
}


def format_response(data_hex, state):
    """Format response with or without CAN header based on ATH state."""
    if not state.get("headers", False):
        return data_hex
    # ATH1: Add CAN header - 7E8 (response ID) + DLC (data length in bytes)
    data_len = len(data_hex) // 2
    return f"7E8{data_len:02X}{data_hex}"


def answer(cmd, state):
    # Нормализация: убираем пробелы, верхний регистр
    c = cmd.replace(" ", "").upper()
    
    # Пустая команда (только \r) — ELM327 отвечает просто промптом
    if c == "":
        return ""  # Специальный маркер: отправить только prompt
    
    # AT-команды
    if c.startswith("ATZ") or c.startswith("ATI"):
        return "ELM327 v1.5"
    if c.startswith("AT@1"):
        return "OBDII to RS232 Interpreter"
    if c.startswith("ATE"):
        state["echo"] = c.endswith("1")
        return "OK"
    if c.startswith("ATRV"):
        return "12.4V"
    if c.startswith("ATDPN"):
        return "A6"
    if c.startswith("ATDP"):
        return "ISO 15765-4 (CAN 11/500)"
    if c == "STI":
        return "STN1170 v3.2.0"
    if c == "VTI":
        return "12.4V"
    if c.startswith("ATL"):      # Linefeeds on/off
        return "OK"
    if c.startswith("ATH"):      # Headers on/off
        state["headers"] = c.endswith("1")
        return "OK"
    if c.startswith("ATS"):      # Spaces on/off
        return "OK"
    if c.startswith("ATM"):      # Memory on/off
        return "OK"
    if c.startswith("ATAT"):     # Adaptive timing
        return "OK"
    if c.startswith("ATSP"):     # Set protocol
        return "OK"
    if c.startswith("ATSH"):     # Set header
        return "OK"
    if c.startswith("ATFC"):     # Flow control
        return "OK"
    if c.startswith("ATFI"):     # Flow control ID
        return "OK"
    if c.startswith("ATFT"):     # Flow control timeout
        return "OK"
    if c.startswith("ATAR"):     # Adapter reset (ISO-TP)
        return "OK"
    if c.startswith("ATCP"):     # CAN protocol (ISO-TP)
        return "OK"
    if c.startswith("ATCRA"):    # CAN receive address
        return "OK"
    if c.startswith("ATFCSH"):   # Flow control send header
        return "OK"
    if c.startswith("ATFCSD"):   # Flow control send data
        return "OK"
    if c.startswith("ATFCSM"):   # Flow control send mode
        return "OK"
    if c.startswith("AT"):
        log(f"UNKNOWN AT: {cmd}")
        return "OK"
    
    # UDS 0x22 ReadDataByIdentifier (VW MEB uses 22xxxx)
    if c.startswith("22"):
        did = c[2:6].upper()  # 4 hex chars
        if did in UDS_DID_RESPONSES:
            return format_response(UDS_DID_RESPONSES[did], state)
        # Generic positive response: 62 + DID + 4 dummy bytes
        return format_response(f"62{did}00000000", state)
    
    # UDS 0x10 Session Control
    if c.startswith("10"):
        return format_response("5003", state)  # Positive response for extended session
    
    # UDS 0x27 Security Access
    if c.startswith("27"):
        return format_response("670100000000", state)  # Seed
    
    # UDS 0x3E Tester Present
    if c.startswith("3E"):
        return format_response("7E", state)
    
    # OBD-II команды
    # Mode 01: Current Data
    if c.startswith("01"):
        # Check exact match first (for 00, 20, 40, 60)
        if c in PID_DATA:
            return format_response(PID_DATA[c], state)
        pid = c[2:4].upper()
        if pid in PID_DATA:
            return format_response(PID_DATA[pid], state)
        # Generic response for unknown PID: 41 + PID + 4 zero bytes
        data = f"41{pid}00000000"
        return format_response(data, state)
    
    # Mode 02: Freeze Frame
    if c.startswith("02"):
        pid = c[2:4].upper()
        data = f"42{pid}00000000"
        return format_response(data, state)
    
    # Mode 03: Stored DTCs
    if c == "03":
        data = "43000000"  # No DTCs
        return format_response(data, state)
    
    # Mode 04: Clear DTCs
    if c == "04":
        return "44"
    
    # Mode 09: Vehicle Info (VIN, Calibration ID)
    if c.startswith("09"):
        if c in PID_DATA:
            return format_response(PID_DATA[c], state)
        pid = c[2:4].upper()
        data = f"49{pid}00000000000000000000000000000000"
        return format_response(data, state)
    
    # Mode 10 (0x10) - could be UDS session control
    if c.startswith("10"):
        return format_response("5003", state)
    
    return "NO DATA"


def handle(conn, addr):
    log(f"=== подключение от {addr[0]}:{addr[1]}")
    state = {"echo": True, "headers": False}
    buf = b""
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            # Log raw data for debugging
            log(f"RAW RX: {data.hex()} | {data!r}")
            buf += data
            while b"\r" in buf:
                raw, buf = buf.split(b"\r", 1)
                cmd = raw.decode("ascii", errors="replace").strip()
                # НЕ пропускаем пустые команды — обрабатываем их
                with lock:
                    seen[cmd] = seen.get(cmd, 0) + 1
                resp = answer(cmd, state)
                
                # Пустая команда -> только prompt
                if resp == "":
                    out = "\r>"
                else:
                    out = (cmd + "\r" if state["echo"] else "") + resp + "\r\r>"
                
                log(f"ПРИЛОЖЕНИЕ> {cmd!r:30}  ОТВЕТ: {resp if resp else '(prompt only)'}")
                
                # Небольшая задержка как у реального адаптера
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
    print("Логер запущен. В Car Scanner: тип Wi-Fi, порт", PORT, "и IP ноутбука:")
    ips = local_ips()
    for ip in ips:
        print(f"    {ip:16} {describe(ip)}")
    if not any(ip.startswith("172.20.10.") for ip in ips):
        print("\n    Адреса 172.20.10.x нет: ноутбук не подключён к точке доступа iPhone?")
    print("\nЕсли приложение не подключается за ~1 минуту, смотрите подсказку ниже.")
    print("Остановка: Ctrl+C\n")

    def hint():
        time.sleep(60)
        if not seen:
            print("\nПОДСКАЗКА: за минуту ни одной команды. Проверьте:")
            print("  1) Брандмауэр Windows: сеть точки доступа обычно 'Общедоступная'. Откройте порт")
            print("     (cmd от администратора):")
            print('     netsh advfirewall firewall add rule name="ELM logger" dir=in action=allow protocol=TCP localport=35000 profile=any')
            print("  2) На iPhone: Настройки -> Конфиденциальность -> Локальная сеть -> разрешите Car Scanner.")
            print("  3) Отключите VPN (AmneziaVPN) на ноутбуке.")
            print("  4) Если не помогает: подключите телефон и ноутбук к домашнему роутеру.\n")
    threading.Thread(target=hint, daemon=True).start()
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\nУникальные команды приложения (количество):")
        for k, v in seen.items():
            print(f"  {k!r}: {v}")
            LOG.write(f"UNIQUE {k!r}: {v}\n")


if __name__ == "__main__":
    main()
