#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vpngate 官方 CSV -> Clash(mihomo) openvpn yaml 输出:
vpngate.yaml(全量) + vpngate-jp/kr/us/th.yaml(分地区)

新增:
  - TCP 可达性检测 (过滤不可用节点)
  - 综合评分排序 (ping + speed + score 加权)
  - 阈值筛选 (ping / speed / score)
  - Mihomo proxy-provider 友好格式
"""
import base64
import csv
import os
import re
import socket
import time
import urllib.request
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml

CSV_URLS = [
    "https://raw.githubusercontent.com/sinspired/VpngateAPI/main/servers.csv",
]
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
REGIONS = ["JP", "KR"]
OUT_ALL = "vpngate.yaml"

# ── 筛选阈值 ──────────────────────────────────────────────
PING_MAX_MS = 250       # 超过此 ping 淘汰
SPEED_MIN_MBPS = 5      # 低于此速度淘汰
SCORE_MIN = 300000      # 低于此分数淘汰
TCP_TIMEOUT = 4         # TCP 连接超时(秒)
TCP_TEST_MAX = 80       # 最多同时测这么多节点

# ── 综合评分权重 ──────────────────────────────────────────
W_PING = 0.40    # ping 越低越好
W_SPEED = 0.35   # 速度越高越好
W_SCORE = 0.25   # VPNGate 原始分数

MAX_NODES = {"ALL": 40, "JP": 30, "KR": 30}


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
    last_err = None
    for url in CSV_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=30) as r:
                text = r.read().decode("utf-8", errors="ignore")
            if "#HostName" in text[:2000]:
                print(f"数据源 OK: {url} ({len(text)} B)")
                return text
            print(f"数据源非CSV, 跳过: {url}")
            last_err = f"非CSV内容: {url}"
        except Exception as e:
            print(f"数据源失败, 换下一个: {url} -> {type(e).__name__}: {e}")
            last_err = e
    raise SystemExit(f"全部数据源失败: {last_err}")


def parse_csv(text: str):
    header, rows = None, []
    for line in text.splitlines():
        line = line.rstrip("\r")
        if line.startswith("#HostName") and "," in line:
            header = [h.lstrip("#").strip() for h in line.split(",")]
            continue
        if not header or line.startswith("*") or not line.strip():
            continue
        vals = next(csv.reader([line]))
        if len(vals) < 11:
            continue
        if len(vals) == 11:
            row = dict(zip(header, vals))
        else:
            # 新格式: 11基础列 + LogType/Operator/Message/OpenVPN_ConfigData_Base64
            extra_header = header + ["LogType", "Operator", "Message", "OpenVPN_ConfigData_Base64"]
            row = dict(zip(extra_header, vals))
        rows.append(row)
    return rows


def tcp_reachable(ip, port, timeout=TCP_TIMEOUT):
    """测试 TCP 端口是否可达，返回 (可达, 延迟ms)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        t0 = time.time()
        sock.connect((ip, port))
        latency = (time.time() - t0) * 1000
        sock.close()
        return True, round(latency, 1)
    except Exception:
        return False, 9999


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
    node["username"] = "vpn"
    node["password"] = "vpn"
    node["ca"] = ca.group(1).replace("\r\n", "\n").replace("\r", "\n").strip()
    try:
        speed = float(d.get("Speed", 0) or 0) / 1e6
    except (ValueError, TypeError):
        speed = 0
    try:
        ping = float(d.get("Ping", 9999) or 9999)
    except (ValueError, TypeError):
        ping = 9999
    try:
        score = int(d.get("Score", 0) or 0)
    except (ValueError, TypeError):
        score = 0
    try:
        uptime = int(d.get("Uptime", 0) or 0)
    except (ValueError, TypeError):
        uptime = 0
    return node, ping, speed, score, uptime


def composite_score(ping, speed, vpngate_score):
    """综合评分 0~1, 越高越好"""
    ping_norm = max(0, (250 - ping) / 250)       # ping 250ms 以下线性衰减
    speed_norm = min(1, speed / 300)             # 300Mbps 封顶
    score_norm = min(1, vpngate_score / 5000000) # 5M 分数封顶
    return ping_norm * W_PING + speed_norm * W_SPEED + score_norm * W_SCORE


def test_nodes(nodes):
    """对节点列表做 TCP 可达性检测, 返回带检测结果的列表"""
    results = []
    tasks = {}
    with ThreadPoolExecutor(max_workers=TCP_TEST_MAX) as pool:
        for node, ping, speed, score, uptime in nodes:
            ip = node["server"]
            port = node["port"]
            future = pool.submit(tcp_reachable, ip, port)
            tasks[future] = (node, ping, speed, score, uptime)
        for future in as_completed(tasks):
            node, ping, speed, score, uptime = tasks[future]
            reachable, tcp_latency = future.result()
            results.append({
                "node": node,
                "ping": ping,
                "speed": speed,
                "score": score,
                "uptime": uptime,
                "tcp_ok": reachable,
                "tcp_latency": tcp_latency,
                "composite": composite_score(
                    ping if ping < 9999 else tcp_latency,
                    speed,
                    score,
                ),
            })
    return results


def filter_and_sort(results):
    """筛选 + 排序, 返回 [(node, note), ...]"""
    filtered = []
    for r in results:
        node = r["node"]
        ping = r["ping"] if r["ping"] < 9999 else r["tcp_latency"]
        speed = r["speed"]
        score = r["score"]

        # 阈值筛选
        if ping > PING_MAX_MS:
            continue
        if speed < SPEED_MIN_MBPS:
            continue
        if score < SCORE_MIN:
            continue
        if not r["tcp_ok"]:
            continue

        country = node["name"].split("-")[1]
        uptime_days = r["uptime"] / 1440
        note = (
            f"# score={score} ping={ping:.0f}ms "
            f"speed={speed:.1f}Mbps uptime={uptime_days:.0f}天 "
            f"country={country}"
        )
        filtered.append((node, note, r["composite"]))

    # 按综合评分降序
    filtered.sort(key=lambda x: x[2], reverse=True)
    return [(n, nt) for n, nt, _ in filtered]


def dump(path: str, nodes):
    lines = ["proxies:"]
    for node, note in nodes:
        lines.append(f"  {note}")
        body = yaml.dump([node], Dumper=_Dumper, allow_unicode=True,
                         sort_keys=False, default_flow_style=False, width=4096).rstrip()
        indented = "\n".join("  " + l if l.strip() else l for l in body.split("\n"))
        lines.append(indented)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    text = fetch_csv()
    rows = parse_csv(text)
    print(f"CSV 行数: {len(rows)}")

    # 解析所有节点
    nodes = []
    for d in rows:
        made = to_node(d)
        if not made:
            continue
        node, ping, speed, score, uptime = made
        nodes.append((node, ping, speed, score, uptime))
    print(f"解析成功: {len(nodes)} 节点")

    # TCP 可达性检测
    print("TCP 可达性检测中...")
    results = test_nodes(nodes)
    reachable = sum(1 for r in results if r["tcp_ok"])
    print(f"TCP 可达: {reachable}/{len(results)}")

    # 筛选 + 排序
    sorted_nodes = filter_and_sort(results)
    print(f"筛选后: {len(sorted_nodes)} 节点")

    by_region = {r: [] for r in REGIONS}
    all_nodes = []
    for node, note in sorted_nodes:
        all_nodes.append((node, note))
        c = node["name"].split("-")[1]
        if c in by_region:
            by_region[c].append((node, note))

    # 全量
    if OUT_ALL:
        cut = all_nodes[:MAX_NODES["ALL"]]
        dump(OUT_ALL, cut)
        print(f"{OUT_ALL}: {len(cut)} 节点")

    # 分地区
    for region, lst in by_region.items():
        path = f"vpngate-{region.lower()}.yaml"
        cut = lst[:MAX_NODES.get(region, 999)]
        dump(path, cut)
        print(f"{path}: {len(cut)} 节点")

    total = sum(len(v) for v in by_region.values())
    if len(all_nodes) < 2:
        raise SystemExit("节点不足 2 个, 判定抓取失败")
    print(f"OK 合计 {total} 个分地区节点")


if __name__ == "__main__":
    main()
