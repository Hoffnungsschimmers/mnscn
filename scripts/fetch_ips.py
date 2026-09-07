#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从订阅链接列表中提取 VLESS 节点 IP:Port
输入: subscriptions.txt（每行一个订阅链接）
输出: addressesapi_fetched.txt（每行一个 IP:Port#备注）
"""
import re
import json
import sys
import requests
from pathlib import Path
from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    """将 sub:// 协议转换为 https://"""
    if url.startswith("sub://"):
        return "https://" + url[6:]
    return url


def fetch_content(url: str) -> str | None:
    """下载订阅内容"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        text = resp.text.strip()
        # 有些订阅返回 base64 编码的整体内容
        if not text.startswith("vless://") and not text.startswith("vmess://"):
            import base64
            try:
                decoded = base64.b64decode(text).decode("utf-8")
                if "://" in decoded:
                    text = decoded
            except Exception:
                pass
        return text
    except Exception as e:
        print(f"  ✗ 下载失败: {e}", file=sys.stderr)
        return None


def extract_ips(content: str) -> list[tuple[str, str]]:
    """
    从订阅内容中提取 VLESS/VMess/Trojan 节点的 IP:Port
    返回 [(server, port_str), ...]
    """
    seen = set()
    results = []

    # 匹配 vless:// / vmess:// / trojan:// 链接
    for match in re.finditer(r"(vless|vmess|trojan)://([^\s#]+)", content):
        scheme = match.group(1)
        payload = match.group(2)

        if scheme == "vmess":
            # vmess 链接格式: vmess://base64({json})，JSON 里有 add / port
            import base64
            try:
                info = json.loads(base64.b64decode(payload).decode("utf-8"))
                server = info.get("add", "").strip()
                port = str(info.get("port", "")).strip()
            except Exception:
                continue
        else:
            # vless / trojan: uuid@server:port?...
            m = re.match(r"[^@]+@([^:]+):(\d+)", payload)
            if not m:
                continue
            server = m.group(1).strip()
            port = m.group(2)

        if not server or not port:
            continue

        key = f"{server}:{port}"
        if key in seen:
            continue
        seen.add(key)
        results.append((server, port))

    return results


def format_output(ips: list[tuple[str, str]]) -> list[str]:
    """格式化为地址库文件每行: IP:Port#自动提取"""
    lines = []
    for server, port in ips:
        lines.append(f"{server}:{port}#自动提取")
    return lines


def main():
    repo_root = Path(__file__).resolve().parent.parent
    sub_file = repo_root / "subscriptions.txt"
    out_file = repo_root / "addressesapi_fetched.txt"

    if not sub_file.exists():
        print(f"✗ 未找到订阅文件: {sub_file}", file=sys.stderr)
        sys.exit(1)

    # 读取订阅链接
    urls = []
    for line in sub_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(normalize_url(line))

    if not urls:
        print("⚠ subscriptions.txt 中没有有效的订阅链接", file=sys.stderr)
        sys.exit(0)

    all_ips = []
    seen = set()

    for url in urls:
        print(f"→ 正在获取: {url}")
        content = fetch_content(url)
        if not content:
            continue
        ips = extract_ips(content)
        print(f"  找到 {len(ips)} 个节点")
        for server, port in ips:
            key = f"{server}:{port}"
            if key not in seen:
                seen.add(key)
                all_ips.append((server, port))

    lines = format_output(all_ips)
    out_file.write_text("\n".join(lines) + "\n" if lines else "", encoding="utf-8")
    print(f"\n✓ 共提取 {len(lines)} 个唯一 IP，已写入: {out_file.name}")


if __name__ == "__main__":
    main()
