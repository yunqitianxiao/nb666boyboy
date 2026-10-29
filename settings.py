"""配置加载：config.yaml 为默认值，config.local.yaml 若存在则深度合并覆盖。

本地覆盖文件不进版本库（见 .gitignore），用来放 token、网卡名、中心地址这类
因机器而异的设置，避免每次改主配置。
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

import yaml


def is_local_endpoint(url: str) -> bool:
    """中心服务是否在本机/局域网内。

    用来决定 HTTP 客户端要不要读代理环境变量。探针向局域网中心上报时如果还走
    ALL_PROXY，会绕一圈甚至直接失败——本机把 ALL_PROXY 写成 `socks://`（httpx 只认
    `socks5://`）时，httpx 在 **构造 Client 的阶段**就抛 ValueError，连重试的机会都没有。
    """
    host = urlsplit(url).hostname or ""
    if host in ("localhost", ""):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # 域名一律当远端，该走代理就走代理
    return ip.is_private or ip.is_loopback or ip.is_link_local


def deep_merge(base: dict, extra: dict) -> dict:
    out = dict(base)
    for key, val in extra.items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], val)
        else:
            out[key] = val
    return out


def load_config(path="config.yaml") -> dict:
    path = Path(path)
    if not path.exists():
        raise SystemExit(f"找不到配置文件 {path}")
    with path.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    local = path.with_name(path.stem + ".local" + path.suffix)
    if local.exists():
        with local.open("r", encoding="utf-8") as fh:
            cfg = deep_merge(cfg, yaml.safe_load(fh) or {})
    return cfg
