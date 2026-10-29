"""CIC-IDS2017 标签归并与归一化，抽样脚本与训练脚本共用同一份，避免两处漂移。"""

from __future__ import annotations

# 原始 15 种标签归并到任务书要求的 6 类。键是 normalize_label() 的输出。
# ★ 映射必须幂等：抽样后的 CSV 里存的就是右边的规范名，训练时再走一遍这个映射
#   必须还是自己，否则整类数据会被当成"不属于六类"静默丢掉（Patator 就踩过这个坑）。
LABEL_MAP = {
    "benign": "BENIGN",
    "portscan": "PortScan",
    "ddos": "DDoS",
    "dos hulk": "DoS Hulk",
    "patator": "Patator",
    "heartbleed": "Heartbleed",
    # 原始名 -> 规范名
    "ftp-patator": "Patator",
    "ssh-patator": "Patator",
}

CLASSES = sorted(set(LABEL_MAP.values()))


def normalize_label(text):
    """小写、空白折叠、各种横线统一成普通短横。

    CIC-IDS2017 的 Web Attack 标签原本用 en dash 分隔，但 Kaggle 上的版本这个字符
    已经被上传者写坏成 U+FFFD（实测 2180 处，正好等于三类 Web Attack 的行数），
    所以 U+FFFD 也要当成横线处理。
    """
    s = str(text).replace("–", "-").replace("—", "-").replace("�", "-")
    return " ".join(s.split()).lower()
