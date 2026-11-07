"""
Разбор elm_log.txt (все подключения) -> car_scanner_protocol_full.json

Запуск:  python parse_elm_log.py [elm_log.txt] [выход.json]

Что делает лучше первого варианта:
  * учитывает ВСЕ подключения и считает их отдельно;
  * отрезает суффикс "числа ответов" (010D1 -> 010D);
  * запоминает, с какими ATSH/ATCRA (адрес шлюза/блока) отправлена каждая команда;
  * оценивает период циклического опроса;
  * AT-команды выделены в свою категорию.
"""
import collections
import json
import re
import sys

LINE = re.compile(r"^(\d\d:\d\d:\d\d) ПРИЛОЖЕНИЕ> (.+?)\s{2,}ОТВЕТ: (.*)$")
CONN = re.compile(r"^(\d\d:\d\d:\d\d) === подключение")

UDS = {"10": "uds_10_session", "19": "uds_19_readDTC", "22": "uds_22_readDataById",
       "27": "uds_27_security", "2E": "uds_2E_write", "31": "uds_31_routine",
       "3E": "uds_3E_testerPresent"}
KWP = {"14": "kwp_14", "18": "kwp_18_readDTC", "1A": "kwp_1A_readECUid", "1F": "kwp_1F"}
OBD = {"01", "02", "03", "04", "06", "07", "09", "0A"}


def normalize(cmd):
    c = cmd.replace(" ", "").upper()
    if (c and not c.startswith(("AT", "ST", "VT"))
            and re.fullmatch(r"[0-9A-F]+", c) and len(c) % 2 == 1):
        c = c[:-1]
    return c


def category(c, caf):
    if c.startswith(("AT", "ST", "VT")):
        return "adapter_setup"
    if not caf:
        return "raw_can_frames"
    mode = c[:2]
    if mode in OBD:
        return f"obd_mode_{mode}"
    return UDS.get(mode) or KWP.get(mode) or "other"


def secs(t):
    h, m, s = map(int, t.split(":"))
    return h * 3600 + m * 60 + s


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "elm_log.txt"
    dst = sys.argv[2] if len(sys.argv) > 2 else "car_scanner_protocol_full.json"

    conns = []          # список подключений
    cats = collections.defaultdict(dict)
    times = collections.defaultdict(lambda: collections.defaultdict(list))  # cmd -> conn -> [t]
    state = None
    day_shift, last_t = 0, 0

    with open(src, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            m = CONN.match(line)
            if m:
                conns.append({"index": len(conns) + 1, "start": m.group(1), "commands": 0,
                              "unique": set()})
                state = {"sh": "7DF", "cra": None, "caf": True}
                continue
            m = LINE.match(line)
            if not m or not conns:
                continue
            t, cmd, resp = secs(m.group(1)), m.group(2).strip().strip("'\""), m.group(3)
            if t < last_t:
                day_shift += 86400
            last_t = t
            c = normalize(cmd)
            if c == "":
                continue
            ci = len(conns)
            conns[-1]["commands"] += 1
            conns[-1]["unique"].add(c)

            # состояние адаптера
            if c.startswith("ATZ"):
                state.update({"sh": "7DF", "cra": None, "caf": True})
            elif c.startswith("ATSH"):
                state["sh"] = c[4:]
            elif c.startswith("ATCRA"):
                state["cra"] = c[5:] or None
            elif c.startswith("ATAR"):
                state["cra"] = None
            elif c.startswith("ATCAF"):
                state["caf"] = c.endswith("1")

            cat = category(c, state["caf"])
            e = cats[cat].setdefault(c, {"count": 0, "per_connection": {}, "contexts": {}, "first_response": resp})
            e["count"] += 1
            e["per_connection"][ci] = e["per_connection"].get(ci, 0) + 1
            if cat != "adapter_setup":
                ctx = f"SH={state['sh']} CRA={state['cra'] or '-'}"
                e["contexts"][ctx] = e["contexts"].get(ctx, 0) + 1
            times[c][ci].append(t + day_shift)

    polling = []
    for c, per in times.items():
        for ci, ts in per.items():
            if len(ts) >= 20 and not c.startswith(("AT", "ST", "VT")):
                period = round((ts[-1] - ts[0]) / (len(ts) - 1), 2)
                polling.append({"command": c, "connection": ci, "count": len(ts),
                                "approx_period_s": period})
    polling.sort(key=lambda p: -p["count"])

    out = {
        "source": src,
        "connections": [{"index": x["index"], "start": x["start"], "commands": x["commands"],
                         "unique": len(x["unique"])} for x in conns],
        "polling": polling,
        "commands_by_category": {k: dict(sorted(v.items())) for k, v in sorted(cats.items())},
    }
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    print(f"Файл: {src} -> {dst}")
    for x in out["connections"]:
        print(f"  подключение {x['index']} ({x['start']}): {x['commands']} команд, {x['unique']} уникальных")
    print("\nКатегории (уникальных / всего):")
    for k, v in sorted(cats.items()):
        print(f"  {k:24} {len(v):4} / {sum(e['count'] for e in v.values())}")
    print("\nЦиклический опрос (>=20 раз за подключение):")
    for p in polling[:25]:
        print(f"  conn {p['connection']}  {p['command']:10} x{p['count']:5}  ~{p['approx_period_s']} с")
    print("\nUDS 0x22 (DID, адрес, число):")
    for c, e in sorted(cats.get("uds_22_readDataById", {}).items()):
        print(f"  {c[2:6]}  {', '.join(e['contexts'])}  x{e['count']}")


if __name__ == "__main__":
    main()
