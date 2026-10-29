"""TCP connect 端口扫描复现（**仅限本人授权实验网段**）。

对目标的一段端口逐个发起连接并立刻关闭，用来验证探针能否把 PortScan 认出来，
并给对照实验提供可知真值的流量。与 nmap 的区别只在于参数完全可控、便于复现。
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from attack.common import add_common_args, guard, pace  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="TCP 端口扫描（仅限授权实验网段）")
    add_common_args(ap)
    ap.add_argument("--start", type=int, default=1)
    ap.add_argument("--end", type=int, default=1024)
    args = ap.parse_args(argv)
    guard(ap, args)

    ports = list(range(args.start, args.end + 1))
    print(f"[扫描] {args.target}:{args.start}-{args.end}，速率 {args.rate}/s，"
          f"预计 {len(ports) / args.rate:.1f}s", flush=True)

    started = time.monotonic()
    opened = []
    for i, port in enumerate(ports):
        if time.monotonic() - started > args.duration:
            print(f"[扫描] 到达时长上限，已发 {i} 个", flush=True)
            break
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.15)
        try:
            if sock.connect_ex((args.target, port)) == 0:
                opened.append(port)
        finally:
            sock.close()
        pace(args.rate, i + 1, started)

    print(f"[扫描] 完成，开放端口：{opened or '（无）'}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
