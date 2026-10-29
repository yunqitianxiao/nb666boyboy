"""M9 协议知识检索：给诊断提示词补上"这类攻击在协议层是怎么回事"。

为什么用字符二元组 BM25 而不是向量库：知识库只有十几条、全是本项目的专业中文段落，
查询词也是固定的类别名加特征名。这种规模下向量检索并不比词面检索好，却要多装 torch、
多下一个模型、多一个失效点。接口保持一致（retrieve(query, top_k)），要换向量库时
只改这一个文件。

中文没有空格，按字切会把"端口扫描"切成四个没有意义的单字，所以用字符二元组。
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

ASCII_WORD = re.compile(r"[a-z0-9][a-z0-9\-_.]*")
CJK = re.compile(r"[一-鿿]+")


def tokenize(text: str) -> list:
    text = text.lower()
    tokens = []
    for run in CJK.findall(text):
        tokens.extend(run[i : i + 2] for i in range(len(run) - 1))
        if len(run) == 1:
            tokens.append(run)
    tokens.extend(ASCII_WORD.findall(text))
    return tokens


class Retriever:
    def __init__(self, chunks_path: str, k1: float = 1.5, b: float = 0.75):
        path = Path(chunks_path)
        if not path.exists():
            raise SystemExit(f"找不到知识库 {path}")
        self.chunks = json.loads(path.read_text(encoding="utf-8"))
        self.k1, self.b = k1, b
        self.docs = [
            tokenize(c["title"] + " " + " ".join(c.get("tags", [])) + " " + c["text"])
            for c in self.chunks
        ]
        self.freqs = [Counter(d) for d in self.docs]
        self.lengths = [len(d) for d in self.docs]
        self.avg_len = sum(self.lengths) / max(len(self.lengths), 1)
        self.n = len(self.chunks)
        df = Counter()
        for f in self.freqs:
            df.update(set(f))
        # 加 1 平滑：某个词在全部文档里都出现时 idf 也不会变成负的
        self.idf = {t: math.log(1 + (self.n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    def score(self, query_tokens, i) -> float:
        f, L = self.freqs[i], self.lengths[i]
        s = 0.0
        for t in query_tokens:
            if t not in f:
                continue
            idf = self.idf.get(t, 0.0)
            s += idf * f[t] * (self.k1 + 1) / (
                f[t] + self.k1 * (1 - self.b + self.b * L / max(self.avg_len, 1e-9))
            )
        return s

    def retrieve(self, query: str, top_k: int = 3) -> list:
        qt = tokenize(query)
        if not qt:
            return []
        scored = [(self.score(qt, i), i) for i in range(self.n)]
        scored.sort(key=lambda x: -x[0])
        out = []
        for s, i in scored[:top_k]:
            if s <= 0:
                continue
            out.append({**self.chunks[i], "score": round(s, 4)})
        return out

    def categories(self) -> list:
        return sorted({t for c in self.chunks for t in c.get("tags", [])})
