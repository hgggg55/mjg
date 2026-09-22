#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vpngate 官方 CSV -> Clash(mihomo) openvpn yaml
输出: vpngate.yaml(全量) + vpngate-jp/kr/us/th.yaml(分地区)
节点按 Score 降序, 命名 VG-{国家}-{IP}, 与 VG2C 同风格
"""
import base64
import csv
import re
import urllib.request
from collections import OrderedDict

import yaml

CSV_URL = "https://www.vpngate.net/api/iphone/"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
REGIONS = ["JP", "KR", "US", "TH"]
OUT_ALL = "vpngate.yaml"


class _Dumper(yaml.SafeDumper):
    pass


def _str_presenter(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _str_presenter)
_Dumper.add_representer(
    OrderedDict,
    lambda dumper, data: dumper.represent_dict(data.items()),
)


def fetch_csv() -> str:
    req = urllib.request.Request(CSV_URL, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", errors="ignore")


def parse_csv(text: str):
    header, rows = None, []
    for line in text.splitlines():
        line = line.rstrip("\r")
        if line.startswith("#Host,"):
            header = [h.lstrip("#").strip() for h in line.split(",")]
            continue
        if not header or line.startswith("*") or not line.strip():
            continue
        vals = next(csv.reader([line]))
        if len(vals) == len(header):
            rows.append(dict(zip(header, vals)))
    return rows


def to_node(d: dict):
    try:
        ovpn = base64.b64decode(d["OpenVPN_ConfigData_Base64"]).decode("utf-8", "ignore")
    except Exception:
        return None
    m = re.search(r"^remote\s+(\S+)\s+(\d+)", ovpn, re.M)
    ca = re.search(r"<ca>(.*?)</ca>", ovpn, re.S)
    if not (m and ca):
        return None
    proto = "udp" if re.search(r"^proto\s+udp", ovpn, re.M) else "tcp"
    cm = re.search(r"^cipher\s+(\S+)", ovpn, re.M)
    am = re.search(r"^auth\s+(\S+)", ovpn, re.M)
    country = d.get("CountryShort", "XX").upper()
    ip = d.get("IP", m.group(1))
    node = OrderedDict()
    node["name"] = f"VG-{country}-{ip}"
    node["type"] = "openvpn"
    node["server"] = m.group(1)
    node["port"] = int(m.group(2))
    node["proto"] = proto
    node["udp"] = True
    if cm:
        node["cipher"] = cm.group(1)
    if am:
        node["auth"] = am.group(1)
    node["ca"] = ca.group(1).strip()
    try:
        speed = float(d.get("Speed", 0) or 0) / 1e6
        speed_s = f"{speed:.1f}Mbps" if speed < 1000 else f"{speed/1000:.1f}Gbps"
    except ValueError:
        speed_s = "?"
    note = (f"# score={d.get('Score', '?')} ping={d.get('Ping', '?')}ms "
            f"speed={speed_s} uptime_min={d.get('Uptime', '?')} "
            f"country={country}")
    return node, note


def dump(path: str, nodes):
    lines = ["proxies:"]
    for node, note in nodes:
        lines.append(f"  {note}")
        body = yaml.dump([node], Dumper=_Dumper, allow_unicode=True,
                         sort_keys=False, default_flow_style=False,
                         width=4096).rstrip()
        indented = "\n".join("  " + l if l.strip() else l for l in body.split("\n"))
        lines.append(indented)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    text = fetch_csv()
    rows = parse_csv(text)
    print(f"CSV 行数: {len(rows)}")
    by_region = {r: [] for r in REGIONS}
    all_nodes = []
    for d in rows:
        made = to_node(d)
        if not made:
            continue
        node, note = made
        all_nodes.append((node, note))
        c = node["name"].split("-")[1]
        if c in by_region:
            by_region[c].append((node, note))
    # 全池按 score 降序
    all_nodes.sort(key=lambda x: int(x[1].split("score=")[1].split(" ")[0]) if "score=" in x[1] else 0, reverse=True)
    dump(OUT_ALL, all_nodes)
    print(f"{OUT_ALL}: {len(all_nodes)} 节点")
    for region, lst in by_region.items():
        lst.sort(key=lambda x: int(x[1].split("score=")[1].split(" ")[0]) if "score=" in x[1] else 0, reverse=True)
        path = f"vpngate-{region.lower()}.yaml"
        dump(path, lst)
        print(f"{path}: {len(lst)} 节点")
    total = sum(len(v) for v in by_region.values())
    if len(all_nodes) < 2:
        raise SystemExit("节点不足 2 个, 判定抓取失败")
    print(f"OK 合计 {total} 个分地区节点")


if __name__ == "__main__":
    main()
