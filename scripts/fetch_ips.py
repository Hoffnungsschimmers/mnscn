#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从多种数据源自动提取 IP:Port，支持：
  1. 订阅地址（返回 vless/vmess/trojan/ss/ssr/hysteria2/tuic 节点链接的 URL）
  2. TXT 网址文件（返回纯文本 IP:Port 的 URL）
  3. 订阅器门户（返回 HTML 页面的 edgetunnel 等订阅器，自动尝试常见端点）
输入: subscriptions.txt（每行一个链接）
输出: addressesapi_fetched.txt（每行一个 IP:Port#备注）
"""
import re
import json
import sys
import base64
from urllib.parse import unquote
import requests
from pathlib import Path

# ---------- 常量 ----------

# 支持的所有代理协议 scheme（含尾部 ://）
SUPPORTED_SCHEMES = [
    "vless://", "vmess://", "trojan://",
    "ss://", "ssr://", "hysteria2://", "hy2://", "tuic://",
]

# 匹配到行尾，因为 # 之后的节点别名可能含空格，而别名里带着地区信息
RE_NODE_LINK = re.compile(
    r"(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic)://[^\r\n]+"
)
RE_REGION = re.compile(
    r"(香港|澳门|台湾|日本|韩国|新加坡|美国|英国|德国|法国|荷兰|俄罗斯|印度|土耳其|加拿大|澳大利亚|巴西|越南|泰国|马来西亚)"
    r"|(?<![A-Za-z])(HK|MO|TW|JP|KR|SG|US|UK|GB|DE|FR|NL|RU|IN|TR|CA|AU|BR|VN|TH|MY)(?![A-Za-z])"
)
RE_IPV4 = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{1,5}))?")
RE_IPV6_BRACKET = re.compile(r"\[([0-9a-fA-F:]+)\]:(\d{1,5})")
RE_DOMAIN = re.compile(
    r"([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})(?::(\d{1,5}))?"
)
RE_HTML_TAG = re.compile(r"<[a-zA-Z/!]")
# uuid@host:port，host 可以是 IPv4、域名或 [IPv6]
RE_NODE_HOSTPORT = re.compile(r"[^@]+@(\[[0-9a-fA-F:]+\]|[^:/?#]+):(\d{1,5})")
USER_AGENT = (
    "v2rayN/edgetunnel "
    "(https://github.com/cmliu/edgetunnel)"
)


# ---------- 工具函数 ----------

def b64_decode_loose(text: str) -> str | None:
    """宽松 base64 解码，兼容标准/URL-safe 及缺失填充"""
    s = text.strip().replace(" ", "")
    if not s:
        return None
    pad = s + "=" * (-len(s) % 4)
    for urlsafe in (False, True):
        try:
            decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
            return decoder(pad).decode("utf-8", errors="replace")
        except Exception:
            continue
    return None


def resolve_sub_url(url: str) -> str:
    """
    解析订阅 URL：
    - sub://BASE64  -> 解码出内部真实 URL
    - 其他          -> 原样返回
    """
    u = url.strip()
    if u.lower().startswith("sub://"):
        inner = b64_decode_loose(u[len("sub://"):])
        if inner:
            inner = inner.strip()
            if inner.startswith("http"):
                return inner
    return u


def decode_subscription(text: str) -> str:
    """解码订阅内容：已是明文则原样返回，否则尝试 base64 解码"""
    t = text.strip()
    if not t:
        return ""
    if "://" in t:
        return t
    decoded = b64_decode_loose(t)
    # 订阅体可能是 base64 包裹的节点链接，也可能是 base64 包裹的纯 IP:Port 列表，
    # 后者解码后不含 "://"，因此不能只用 "://" 判断解码是否成功。
    if decoded and (
        "://" in decoded
        or RE_IPV4.search(decoded)
        or RE_IPV6_BRACKET.search(decoded)
    ):
        return decoded
    return t


def is_html(text: str) -> bool:
    """判断内容是否为 HTML"""
    return bool(RE_HTML_TAG.search(text[:2000]))


def fetch_raw(url: str) -> str | None:
    """下载 URL 原始内容"""
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.text.strip()
    except Exception as e:
        print(f"  X 下载失败: {e}", file=sys.stderr)
        return None


def detect_type(content: str) -> str:
    """
    自动识别内容类型:
      "nodes" - 包含 vless/vmess/trojan 等节点链接
      "txt"   - 纯文本 IP:Port 列表
      "html"  - HTML 页面
      "unknown"
    """
    text = decode_subscription(content)

    if RE_NODE_LINK.search(text):
        return "nodes"

    # 检查纯文本 IP:Port
    ip_lines = sum(
        1 for line in text.splitlines()
        if RE_IPV4.match(line.strip())
        or RE_IPV6_BRACKET.match(line.strip())
        or RE_DOMAIN.match(line.strip())
    )
    if ip_lines >= 3:
        return "txt"

    if is_html(content):
        return "html"

    return "unknown"


# ---------- 解析函数 ----------

def pick_region(text: str) -> str:
    """从节点别名里挑出地区标记，取不到就返回空字符串"""
    if not text:
        return ""
    name = unquote(text).strip()
    m = RE_REGION.search(name)
    if m:
        return m.group(0).upper() if m.group(2) else m.group(0)
    return ""


def extract_from_nodes(content: str) -> list[tuple[str, str, str]]:
    """从订阅内容提取节点，返回 [(server, port, remark), ...]"""
    text = decode_subscription(content)
    seen = set()
    results = []

    for match in RE_NODE_LINK.finditer(text):
        link = match.group(0)
        scheme_end = link.index("://")
        scheme = link[:scheme_end + 3]
        payload = link[scheme_end + 3:]

        server, port = None, None
        # #号后是节点别名，地区信息通常在这里
        remark = pick_region(payload.split("#", 1)[1] if "#" in payload else "")

        if scheme == "vmess://":
            decoded = b64_decode_loose(payload.split("#", 1)[0])
            if not decoded:
                continue
            try:
                info = json.loads(decoded)
                server = (info.get("add") or "").strip()
                port = str(info.get("port") or "").strip()
                if not remark:
                    remark = pick_region(str(info.get("ps") or ""))
            except Exception:
                continue

        elif scheme == "ssr://":
            decoded = b64_decode_loose(payload.split("#", 1)[0])
            if not decoded:
                continue
            # ssr://server:port:protocol:method:obfs:base64pass/?params
            slash_idx = decoded.find("/?")
            main_part = decoded[:slash_idx] if slash_idx >= 0 else decoded
            segments = main_part.split(":")
            if len(segments) >= 6:
                server = segments[0]
                port = segments[1]

        elif scheme in ("ss://",):
            # ss:// 可能是 ss://base64(method:pass@host:port)#name
            clean = payload.split("#")[0].split("?")[0]
            decoded = b64_decode_loose(clean)
            # SIP002 形式的 ss:// 主体是明文 host:port，不需要解码
            hostport_src = decoded if (decoded and "@" in decoded) else clean
            if "@" in hostport_src:
                hostport = hostport_src.rsplit("@", 1)[-1]
                m = RE_NODE_HOSTPORT.match("x@" + hostport)
                if m:
                    server = m.group(1)
                    port = m.group(2)

        else:
            # vless / trojan / hysteria2 / hy2 / tuic: uuid@server:port?...
            clean = payload.split("#")[0]
            m = RE_NODE_HOSTPORT.match(clean)
            if m:
                server = m.group(1).strip()
                port = m.group(2)

        if not server or not port:
            continue
        # 跳过非数字端口
        if not port.isdigit():
            continue
        # 跳过明显不是 IP/域名的 server（含空格等异常字符）
        if " " in server or not server:
            continue

        key = f"{server}:{port}"
        if key in seen:
            continue
        seen.add(key)
        results.append((server, port, remark))

    return results


def extract_from_txt(content: str) -> list[tuple[str, str, str]]:
    """从纯文本提取 IP:Port 列表"""
    content = decode_subscription(content)
    seen = set()
    results = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        # #号后是已有备注（如 #JP），保留下来而不是丢弃
        body, _, existing = line.partition("#")
        body = body.strip()
        remark = existing.strip()
        if not body:
            continue

        server, port = None, None

        # 优先 IPv6 方括号: [2606:...]:443
        m6 = RE_IPV6_BRACKET.match(body)
        if m6:
            server = f"[{m6.group(1)}]"
            port = m6.group(2)
        else:
            # IPv4
            m4 = RE_IPV4.match(body)
            if m4:
                server = m4.group(1)
                port = m4.group(2) or "443"
            else:
                # 域名
                md = RE_DOMAIN.match(body)
                if md:
                    server = md.group(1)
                    port = md.group(2) or "443"

        if not server or not port:
            continue

        key = f"{server}:{port}"
        if key in seen:
            continue
        seen.add(key)
        results.append((server, port, remark))

    return results


def extract_from_html(content: str) -> list[tuple[str, str, str]]:
    """从 HTML 页面中提取：先找内嵌节点，再递归抓取子链接"""
    # 1) 直接在 HTML 里找节点链接
    node_ips = extract_from_nodes(content)
    if node_ips:
        return node_ips

    # 2) 从 HTML 提取 URL，递归获取
    url_pattern = re.compile(r"(https?://[^\s\"'<>]+)")
    found_urls = set()
    for m in url_pattern.finditer(content):
        url = m.group(1)
        # 排除 CSS/JS/图片等
        if re.search(r"\.(css|js|png|jpg|gif|svg|ico|woff|ttf|map)", url, re.I):
            continue
        found_urls.add(url)

    for url in list(found_urls)[:10]:
        raw = fetch_raw(url)
        if not raw:
            continue
        stype = detect_type(raw)
        if stype == "nodes":
            return extract_from_nodes(raw)
        elif stype == "txt":
            return extract_from_txt(raw)

    return []


# ---------- edgetunnel 门户自动探测 ----------

def try_edgetunnel_endpoints(base_url: str) -> list[tuple[str, str, str]]:
    """
    对 edgetunnel 类订阅器，自动尝试常见端点获取节点：
    /auto -> /sub?token=auto -> /sub?host=&uuid=
    """
    base = base_url.rstrip("/")
    endpoints = [
        f"{base}/auto",
        f"{base}/sub?token=auto",
    ]
    for ep in endpoints:
        raw = fetch_raw(ep)
        if not raw:
            continue
        stype = detect_type(raw)
        if stype == "nodes":
            return extract_from_nodes(raw)
        elif stype == "txt":
            return extract_from_txt(raw)
    return []


# ---------- 输出 ----------

def format_output(ips: list[tuple[str, str, str]]) -> list[str]:
    """格式化为: IP:Port#备注（无备注时回落为 auto）"""
    return [f"{s}:{p}#{r or 'auto'}" for s, p, r in ips]


# ---------- 主流程 ----------

def main():
    repo_root = Path(__file__).resolve().parent.parent
    sub_file = repo_root / "subscriptions.txt"
    out_file = repo_root / "addressesapi_fetched.txt"

    if not sub_file.exists():
        print(f"X 未找到: {sub_file}", file=sys.stderr)
        sys.exit(1)

    # 读取订阅源列表
    sources = []
    for line in sub_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sources.append(line)

    if not sources:
        print("W subscriptions.txt 为空", file=sys.stderr)
        sys.exit(0)

    all_ips = []
    seen = set()

    for raw_url in sources:
        # 先解码 sub:// 协议
        url = resolve_sub_url(raw_url)
        print(f"-> {url}")

        content = fetch_raw(url)
        if not content:
            continue

        source_type = detect_type(content)
        print(f"   类型: {source_type}")

        if source_type == "nodes":
            ips = extract_from_nodes(content)
        elif source_type == "txt":
            ips = extract_from_txt(content)
        elif source_type == "html":
            print("   尝试 edgetunnel 端点...")
            ips = try_edgetunnel_endpoints(url)
            if not ips:
                ips = extract_from_html(content)
        else:
            print("   W 无法识别，跳过")
            continue

        # IP:Port 去重
        count = 0
        for server, port, remark in ips:
            key = f"{server}:{port}"
            if key not in seen:
                seen.add(key)
                all_ips.append((server, port, remark))
                count += 1
        print(f"   提取 {len(ips)} 个，去重后新增 {count} 个")

    lines = format_output(all_ips)
    out_file.write_text("\n".join(lines) + "\n" if lines else "", encoding="utf-8")
    print(f"\nV 共 {len(all_ips)} 个唯一 IP -> {out_file.name}")


if __name__ == "__main__":
    main()
