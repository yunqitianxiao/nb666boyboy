"""M6 边缘侧的上报通道：把一批流特征 POST 给中心服务。

批次格式刻意带上 `feature_names`，让中心端能当场比对训练时的列序。列序一旦错位，
模型不会报错——它只会把"目的端口"当成"流时长"去推理，然后给出一个看起来正常的错误答案。
中心端收到列序不符直接拒收，比事后查线上准确率便宜得多。
"""

from __future__ import annotations

import time

import httpx

try:
    from settings import is_local_endpoint
except ImportError:  # 直接 python probe/sniffer.py 时的退路
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from settings import is_local_endpoint


class Reporter:
    def __init__(self, center_url: str, token: str, probe_id: str, timeout: float = 5.0):
        self.url = center_url.rstrip("/") + "/api/v1/report"
        self.token = token
        self.probe_id = probe_id
        self.timeout = timeout
        self.sent = 0
        self.failed = 0
        self.unreachable = 0
        try:
            self._client = httpx.Client(
                timeout=timeout, trust_env=not is_local_endpoint(center_url)
            )
        except ValueError as exc:
            raise SystemExit(
                f"HTTP 客户端初始化失败：{exc}\n"
                f"中心地址 {center_url} 不在本机/局域网内，因此走了代理环境变量；"
                f"请检查 ALL_PROXY 的写法（httpx 只认 socks5://，不认 socks://）。"
            )

    def close(self) -> None:
        self._client.close()

    def send(self, feature_names, flows, window) -> dict | None:
        """flows: [(key, first_seen, last_seen, values)]；返回中心端回执，失败返回 None。"""
        if not flows:
            return None
        payload = {
            "probe_id": self.probe_id,
            "sent_at": time.time(),
            "window": window,
            "feature_names": list(feature_names),
            "flows": [
                {
                    "key": "|".join(str(p) for p in key),
                    "first_seen": first,
                    "last_seen": last,
                    "values": values,
                }
                for key, first, last, values in flows
            ],
        }
        try:
            resp = self._client.post(
                self.url,
                json=payload,
                headers={"X-Probe-Token": self.token},
            )
        except httpx.HTTPError as exc:
            self.unreachable += 1
            print(f"[上报] 中央服务不可达：{exc}", flush=True)
            return None
        if resp.status_code != 200:
            self.failed += 1
            print(f"[上报] 中心端返回 {resp.status_code}：{resp.text[:200]}", flush=True)
            return None
        self.sent += len(flows)
        return resp.json() if resp.content else None


