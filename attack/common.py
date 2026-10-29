"""攻击复现的安全护栏。

这三支脚本只为验证本项目的检测链路而存在，**只允许在本人授权的实验网段内运行**。
护栏做两件事：

1. 目标必须是私有地址（RFC1918 或回环）。往公网发包是违法的，不是"实验"。
2. 必须显式传 --i-am-authorized。少打一个字就拒绝运行，比事后道歉便宜。

另外统一限定持续时间与速率上限，避免误操作把实验网段打瘫。
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
import time


def add_common_args(ap: argparse.ArgumentParser) -> argparse.ArgumentParser:
    ap.add_argument("target", help="目标 IPv4 地址，必须是私有网段")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--duration", type=float, default=10.0, help="持续秒数，上限 60")
    ap.add_argument("--rate", type=float, default=200.0, help="每秒发包数上限 5000")
    ap.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="确认目标属于本人的实验网段（不加这个参数不会发任何包）",
    )
    return ap


def guard(ap: argparse.ArgumentParser, args) -> None:
    if not args.i_am_authorized:
        ap.error("必须显式加 --i-am-authorized 确认目标属于本人授权的实验网段")
    try:
        ip = ipaddress.ip_address(args.target)
    except ValueError:
        ap.error(f"{args.target} 不是合法 IPv4 地址（不要传域名，避免打到公网）")
    if not (ip.is_private or ip.is_loopback):
        ap.error(f"{ip} 不是私有/回环地址。本工具只允许在实验网段使用。")
    if args.duration > 60:
        ap.error("--duration 上限 60 秒")
    if args.rate > 5000:
        ap.error("--rate 上限 5000 包/秒")


def resolve_self_ip(target: str) -> str:
    """探一条 UDP 路由拿到本机出口 IP（不发实际数据包）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    finally:
        s.close()


def pace(rate: float, sent: int, started: float) -> None:
    """按目标速率限速：睡到"按当前速率应该到达的时刻"。"""
    target_t = started + sent / rate
    now = time.monotonic()
    if target_t > now:
        time.sleep(target_t - now)


def require_root() -> None:
    import os

    # Windows 没有 geteuid：scapy 走 Npcap，"权限"就是进程是否以管理员启动，
    # 进程内部查不出来，交给发包失败时的异常。
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() != 0:
        sys.exit("构造原始包需要 root 权限")
