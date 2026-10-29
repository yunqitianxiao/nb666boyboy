"""M1/M6 边缘探针：抓包 → 解析 → 聚成流 → 周期性上报中心服务。

用法::

    sudo python3 -m probe.sniffer --iface eth0 --center http://127.0.0.1:8000
    # 只看不报（验证抓包与特征是否正常）
    python3 -m probe.sniffer --iface eth0 --dry-run
    # 顺便落 pcap 和特征 CSV，供报告与 Wireshark 对照
    sudo python3 -m probe.sniffer --iface eth0 --pcap data/pcap/run.pcap --csv data/features/run.csv

抓包需要 root 或 CAP_NET_RAW。

一点实现上的取舍：上报发生在**流结束时**（FIN/RST、120 s 空闲、或存活超过 --max-age）。
按窗口上报活跃流会让同一条流被重复判定、重复告警，而特征也还没定型。
代价是长连接会被 --max-age 截成几段，每段时长只是真实时长的一部分——这个口径要在报告里写清楚。
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

from probe.features import FEATURE_ORDER, FlowTable, PacketRecord, flow_features, to_vector

try:
    from probe.reporter import Reporter
except ImportError:  # 直接 python probe/sniffer.py 时的退路
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from probe.reporter import Reporter


def load_feature_names(path: str | None) -> list:
    """列序从训练产物里取，不在这里另抄一份。抄一份就等于埋了一个会静默漂移的副本。"""
    if not path:
        return list(FEATURE_ORDER)
    p = Path(path)
    if not p.exists():
        raise SystemExit(f"找不到特征 schema：{p}（先跑 models/train.py 生成）")
    schema = json.loads(p.read_text(encoding="utf-8"))
    names = schema.get("feature_names")
    if not names:
        raise SystemExit(f"{p} 里没有 feature_names")
    return names


def to_record(pkt) -> PacketRecord | None:
    """把 scapy 包转成 PacketRecord。不认识的协议返回 None（不参与建模）。"""
    from scapy.layers.inet import IP, TCP, UDP

    if IP not in pkt:
        return None
    ip = pkt[IP]
    ip_hdr = int(ip.ihl or 5) * 4
    total_len = int(ip.len) if ip.len else len(bytes(ip))

    if TCP in pkt:
        tcp = pkt[TCP]
        tcp_hdr = int(tcp.dataofs or 5) * 4
        return PacketRecord(
            ts=float(pkt.time),
            src_ip=ip.src, src_port=int(tcp.sport),
            dst_ip=ip.dst, dst_port=int(tcp.dport),
            proto=6,
            length=total_len,
            header_len=ip_hdr + tcp_hdr,
            payload_len=max(total_len - ip_hdr - tcp_hdr, 0),
            tcp_flags=int(tcp.flags),
            tcp_window=int(tcp.window),
            tcp_header_len=tcp_hdr,
        )
    if UDP in pkt:
        udp = pkt[UDP]
        return PacketRecord(
            ts=float(pkt.time),
            src_ip=ip.src, src_port=int(udp.sport),
            dst_ip=ip.dst, dst_port=int(udp.dport),
            proto=17,
            length=total_len,
            header_len=ip_hdr + 8,
            payload_len=max(total_len - ip_hdr - 8, 0),
        )
    return None


class Probe:
    def __init__(self, args, feature_names):
        self.args = args
        self.feature_names = feature_names
        self.table = FlowTable(max_flows=args.max_flows)
        self.reporter = None
        if not args.dry_run:
            self.reporter = Reporter(args.center, args.token, args.probe_id)
        self.running = threading.Event()
        self.running.set()
        self.packets = 0
        self.flows_sent = 0
        self.alerts = 0
        self._pcap_writer = None
        self._csv = None
        self._csv_writer = None
        if args.csv:
            import csv

            Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
            self._csv = open(args.csv, "a", newline="", encoding="utf-8")
            self._csv_writer = csv.writer(self._csv)
            if self._csv.tell() == 0:
                self._csv_writer.writerow(["first_seen", "last_seen", "flow_key"] + feature_names)

    # ---------------------------------------------------------------- 抓包

    def handle(self, pkt):
        rec = to_record(pkt)
        if rec is None:
            return
        self.table.add(rec)
        self.packets += 1
        if self._pcap_writer is not None:
            self._pcap_writer.write(pkt)
        if self.args.count and self.packets >= self.args.count:
            self.running.clear()

    # ---------------------------------------------------------------- 上报

    def flush(self, now: float) -> None:
        flows = self.table.expire(now, max_age=self.args.max_age)
        if not flows:
            return
        batch = []
        for flow in flows:
            feats = flow_features(flow)
            batch.append((flow.key, flow.start, flow.last, to_vector(feats, self.feature_names)))
            if self._csv_writer:
                self._csv_writer.writerow(
                    [flow.start, flow.last, "|".join(str(p) for p in flow.key)]
                    + [feats[n] for n in self.feature_names]
                )
        if self._csv:
            self._csv.flush()
        if not batch:
            return
        if self.reporter is None:
            self.flows_sent += len(batch)
            return
        receipt = self.reporter.send(
            self.feature_names,
            batch,
            {"start": now - self.args.window, "end": now},
        )
        self.flows_sent += len(batch)
        if receipt:
            self.alerts += int(receipt.get("alerts", 0))

    def _flush_loop(self):
        while self.running.is_set():
            time.sleep(self.args.window)
            try:
                self.flush(time.time())
            except Exception as exc:  # 单次上报失败不能把探针打死
                print(f"[探针] 本轮上报异常：{exc}", flush=True)

    # ---------------------------------------------------------------- 主循环

    def run(self):
        from scapy.all import sniff
        from scapy.utils import PcapWriter

        if self.args.pcap:
            Path(self.args.pcap).parent.mkdir(parents=True, exist_ok=True)
            self._pcap_writer = PcapWriter(self.args.pcap, append=True, sync=True)

        flusher = threading.Thread(target=self._flush_loop, daemon=True)
        flusher.start()
        print(
            f"[探针] 开始抓包 iface={self.args.iface or 'auto'} 窗口 {self.args.window}s "
            f"上报={'否（--dry-run）' if self.args.dry_run else self.args.center}",
            flush=True,
        )
        try:
            sniff(
                iface=self.args.iface,
                filter=self.args.bpf or None,
                prn=self.handle,
                store=False,
                stop_filter=lambda _: not self.running.is_set(),
            )
        except KeyboardInterrupt:
            pass
        except PermissionError:
            raise SystemExit("抓包需要 root 或 CAP_NET_RAW 权限")
        finally:
            self.running.clear()
            time.sleep(self.args.window + 0.1)
            self.flush(time.time())
            if self._pcap_writer:
                self._pcap_writer.close()
            if self._csv:
                self._csv.close()
            if self.reporter:
                self.reporter.close()
            print(
                f"[探针] 结束：抓包 {self.packets} 个，上报流 {self.flows_sent} 条，"
                f"告警 {self.alerts} 条，流表淘汰 {self.table.dropped} 条",
                flush=True,
            )


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="NetSentinel-LLM 边缘探针")
    ap.add_argument("--iface", default=None, help="网卡名；不给则自动挑")
    ap.add_argument("--center", default="http://127.0.0.1:8000")
    ap.add_argument("--token", default=None, help="不传则读 NETSENTINEL_TOKEN 环境变量")
    ap.add_argument("--probe-id", default=socket.gethostname())
    ap.add_argument("--bpf", default="", help="BPF 过滤表达式")
    ap.add_argument("--window", type=float, default=2.0, help="上报周期（秒）")
    ap.add_argument("--max-flows", type=int, default=5000)
    ap.add_argument("--max-age", type=float, default=30.0, help="单条流最长存活秒数，超过即截断上报")
    ap.add_argument("--feature-names", default="models/artifacts/feature_schema.json")
    ap.add_argument("--pcap", default=None)
    ap.add_argument("--csv", default=None)
    ap.add_argument("--dry-run", action="store_true", help="不连中心服务，只抓包与算特征")
    ap.add_argument("--count", type=int, default=0, help="抓够 N 个包即退出（自测用）")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.token is None:
        args.token = os.environ.get("NETSENTINEL_TOKEN")
    if not args.dry_run and not args.token:
        raise SystemExit("未提供 token：--token 或环境变量 NETSENTINEL_TOKEN（--dry-run 可跳过）")

    feature_names = load_feature_names(args.feature_names)
    Probe(args, feature_names).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
