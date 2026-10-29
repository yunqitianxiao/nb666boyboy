# NetSentinel-LLM —— 智能网络流量嗅探分析及大语言模型诊断系统

> 《计算机网络》课程设计（自选题目）
> 基于 Scapy 与机器学习的智能网络流量嗅探分析及大语言模型诊断系统

传统嗅探程序只负责"看见"网络，机器学习负责"判断"异常，大语言模型负责"解释"结果并给出处置建议。
对应智能体范式的感知（抓包）→ 思考（分类）→ 行动（诊断）→ 反馈（看板）。

---

## 一、这个系统能干什么

### 1. 打开看板（`streamlit run dashboard/app.py`）能看到什么

| 面板 | 内容 |
|---|---|
| 实时总览 | 顶部四个数字块（会话数 / 告警数 / 高危数 / 探针数）；每 10 s 的流数量折线；小模型判定分布与协议构成两个横向条形图，柱上直接标数值 |
| 会话流水表 | 最近 200 条会话，逐条显示时间、探针、协议、源/目的 IP 与端口、流时长、前后向包数、判定类别、置信度 |
| 告警 | 时间、探针编号、类别（PortScan / DDoS / DoS Hulk / Patator 等）、**来源（小模型 / 规则）**、置信度或超阈值倍数、风险等级；点开某行看证据 |
| 诊断报告 | 中文报告五个固定部分：事件概述、风险等级、证据链、处置建议、协议原理回顾 |
| 聊天助手 | 侧栏「打开聊天助手」点开一个对话框，可以问看板现状（数字由中心端从库里现拍快照带进提示词）、问协议原理、问处置顺序；多轮对话 |
| 历史查询 | 按时间范围、探针、类别过滤历史告警与报告，结果可导出 CSV |

实时面板每 2 s 自动刷新（`st.fragment(run_every=2.0)`），数据来自中心服务的 `/api/v1/stats` 与 `/api/v1/flows`。

### 2. 命令行能做什么

```bash
# 探针：抓包 + 会话聚合 + 上报中心
python -m probe.sniffer --iface eth0 --center http://127.0.0.1:8000 --token <TOKEN>
# 同时把原始帧存成 pcap、把会话特征写成 CSV，供报告与 Wireshark 对照
```

### 3. 中心服务能做什么（`/docs` 有自动生成的接口文档）

| 接口 | 用途 |
|---|---|
| `POST /api/v1/report` | 探针上报会话特征批次（Token 鉴权） |
| `GET /api/v1/flows` | 会话流水表（最近 N 条，只回展示用特征列） |
| `GET /api/v1/alerts` | 查询告警（按时间/探针/类别过滤） |
| `POST /api/v1/diagnose` | 对指定告警触发/重跑 LLM 诊断 |
| `POST /api/v1/assistant` | 看板助手：带看板快照与对话历史的自由问答 |
| `GET /api/v1/stats` | 看板用的统计数据（协议分布、时序、汇总、规则引擎计数） |

### 4. 训练与评估能做什么

```bash
# 默认口径：随机划分（快，但指标会被重复流抬高，只适合验证链路能跑通）
python models/train.py --data data/cicids2017_sample.csv --out models/artifacts
# 报告用的口径：类内按时间划分 + 前向滚动验证选型
python models/train.py --data data/cicids2017_sample.csv --split temporal-cv
# 只跑一两个模型，快速验证链路
python models/train.py --data data/cicids2017_sample.csv --only decision_tree hybrid_forest
# DART 消融（残差相关，单列一节写进报告）
python models/train.py --data data/cicids2017_sample.csv --dart-ablation
# 跨天留出实验（开集问题，结论见 docs/architecture.md）
python3 tools/cross_day_eval.py
# M11 规则基线（与小模型同一段测试集，报告要用的对照数字）
python3 tools/rules_baseline.py --data data/cicids2017_sample.csv
```

输出五模型（决策树 / 随机森林 / XGBoost / 逻辑回归 / 混合森林）同口径对比表、每类 P/R/F1、混淆矩阵、树数、训练耗时，按**滚动验证均值**选出最优模型落地为 `best_model.pkl`（最后 10% 的测试集全程封存，只作最终汇报，不参与选型）。

`--split` 三档：`random`（分层随机，默认）/ `temporal`（类内按时间 70/20/10，单段验证集）/ `temporal-cv`（再把开发段切 5 块做前向滚动验证，报告用这档）。**为什么不能用随机划分下的 0.999 当结论**见 `docs/architecture.md`"实测结果"一节：随机划分下 XGBoost 与一棵决策树只差 0.0002。

两个容易报错的口径，代码里已经钉住：

- **树数**：XGBoost / LightGBM 多分类每轮每类各长一棵树，CatBoost 每轮只长一棵（多维叶子）。混合森林 24 个基学习器实测 10400 棵，不是「24 × 100」。
- **标签**：XGBoost 的 sklearn 接口只吃 `0..K-1` 整数，所以统一编码一次；`predict()` 返回的是下标，必须过 `artifact["classes"][pred]` 才是类名。

**什么是混合森林（第五个模型）**：Bagging 骨架不变（bootstrap 采样 + 随机特征子集，深度约束 24 层），但每个基学习器不再是一棵 CART，而是从 XGBoost / LightGBM / CatBoost 中**随机抽一个**训练出的小型提升模型（内部浅树 6 层、100 轮），最后软投票聚合。动机是让 Bagging 压方差、Boosting 压偏差两头都管。结构与对比见 `docs/figures/fig2b_hybrid_forest.png`。

### 5. 攻击复现能做什么（**仅限本人授权实验网段**）

`attack/portscan.py`、`attack/synflood.py`、`attack/pingflood.py` 用 scapy 自构造攻击流量，
用来验证检测链路与做对照实验；nmap 仅作对照组。

---

## 二、系统分层

```
展示层  Streamlit 看板（M5 / M10）
   ▲ 告警与报告实时推送
大模型层  DeepSeek（主）/ 通义千问（备），专家提示词 + 固定输出 schema（M4）
   ▲ ▼ 诊断请求 / 结构化报告
中心层  云服务器 FastAPI：上报鉴权 · SQLite · 小模型推理 · RAG（M3 / M6 / M9 / M8 / M11）
   ▲ ▼ HTTP/JSON 上报 · 告警回执
边缘层  两台 PC 探针：抓包解析 · 会话特征 · 攻击复现（M1 / M2 / M7）
   ▲ 原始以太网帧
实验网段  正常业务流量 + 攻击流量
```

图见 `docs/figures/`：

| 文件 | 内容 | 报告中的位置 |
|---|---|---|
| `fig1_architecture.png` | 系统总体架构图（分层 + 数据流） | 3.2 系统架构 |
| `fig2_ml_model.png` | 小模型结构图（离线训练 + 在线推理） | 4.x 小模型 |
| `fig2b_hybrid_forest.png` | 混合森林内部结构（Bagging 骨架 + 随机基学习器） | 4.x 混合森林 |
| `fig3_llm_pipeline.png` | 大模型诊断管线图（RAG → 提示词 → 结构化输出） | 4.x LLM 诊断 |

重绘：`python3 docs/make_figures.py`

---

## 三、目录结构与分工

```
netsentinel-llm/
├── probe/        边缘探针      sniffer.py 抓包解析 / features.py 会话特征 / reporter.py 上报
├── center/       中心服务      main.py API / database.py 存储 / inference.py 推理 / rules.py 规则引擎
├── llm/          大模型        prompts.py 提示词 / client.py API 客户端 / schema.py 输出校验 / rag.py 检索
├── tools/        数据工具      build_sample.py 抽六类小样本 / cross_day_eval.py 跨天留出 / rules_baseline.py 规则基线
├── models/       小模型        train.py 训练与选型 / hybrid_forest.py 混合森林 / artifacts/ 模型产物
├── attack/       攻击复现      common.py 安全护栏 / portscan.py / synflood.py / pingflood.py
├── dashboard/    看板          app.py
├── data/         数据          cicids2017_sample.csv / pcap/ / features/ / rag/chunks.json
├── docs/         文档与图      architecture.md / make_figures.py / figures/
├── tests/        自测
├── settings.py   配置加载（config.yaml + config.local.yaml 深合并）
└── config.yaml  requirements.txt  README.md
```

规则引擎（M11）分两组判据：单流规则（包长/时长/包数）与现场行为规则（同一源在 60 秒内探了
多少不同目的端口、同一目的端口上未应答的 SYN 流数）。两条实现约定：**扫描类规则按源 IP、
洪泛类按目的 IP:端口 共用一个去重域**，一次扫描只报一条告警；**规则不输出置信度**，
告警表 `source='rule'` 的行里 `confidence` 存的是"超出阈值多少倍"。

| 模块 | 名称 | 主责 |
|---|---|---|
| M1 | 数据包嗅探与协议解析 | 同学 A |
| M2 | 流量特征工程 | 同学 B |
| M3 | 小模型攻击检测 | 同学 B |
| M4 | LLM 自然语言诊断 | 同学 B |
| M5 | Web 可视化看板 | 同学 B |
| M6 | 中心服务与边缘探针通信 | 同学 A |
| M7 | 攻击复现实验台 | 同学 A |
| M8 | 模型对比实验（五模型，含混合森林） | 同学 B |
| M9 | RAG 协议知识库 | 同学 B |
| M10 | 双探针联动演示 | 同学 A |
| M11 | 阈值规则引擎基线 | 同学 B |

---

## 四、数据集

用 CIC-IDS2017 官方的 8 个 `MachineLearningCVE` CSV（共 2,830,743 行、79 列、844 MB）。

```bash
# 1) 下载原始 CSV（Kaggle 镜像，官方 UNB 直链已不再提供 zip）
mkdir -p data/raw/cicids2017
kaggle datasets download -d shadman1028/cicids2017-official-flow-feature-csv-files \
    -p data/raw/cicids2017 --unzip

# 2) 抽样成六类小样本（约 25 万行、87 MB）
python3 tools/build_sample.py
# 清单写在 data/cicids2017_sample_manifest.json：每类行数、配额、种子、已知问题
```

**为什么按类配额抽、不按比例抽**：全量里 BENIGN 占 80.3%，Heartbleed 只有 **11 行**。按 8.8% 的比例抽到 25 万行，
Heartbleed 只剩 1 行，7:2:1 划分后测试集 0 行 —— 这个类等于被抹掉了。所以常见类截断、稀有类全收。

**这条必须写进报告**：训练集的类别先验被抬高了（BENIGN 从 80.3% 降到 47.3%），
所以本样本上的准确率**不能当作线上准确率**。真实部署里 80% 是正常流量，误报率的含义完全不同。

另外两个已知数据问题（`data/cicids2017_sample_manifest.json` 里也记了）：

- 三个 Web Attack 标签里的 en dash 已被上传者写坏成 `U+FFFD`（2180 处，正好等于这三类的行数）。它们不属于六类，抽取时已丢弃；`normalize_label()` 兼容了这个字符。
- 原文件列名带前导空格（`' Destination Port'`），抽样时已去掉。

---

## 五、快速开始

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp config.yaml config.local.yaml      # 填入自己的 token 与 API key 环境变量名
export DEEPSEEK_API_KEY=sk-...

python models/train.py --data data/cicids2017_sample.csv
uvicorn center.main:app --port 8000
python -m probe.sniffer --iface eth0 --center http://127.0.0.1:8000
streamlit run dashboard/app.py

# 没有 CAP_NET_RAW 时，用回放顶替"抓包"这一环（其余全部走真实代码路径）
python3 tools/replay_live.py --center http://127.0.0.1:8000 --rate 2 --burst 2 --attack-every 10
```

抓包需要 root 或 `CAP_NET_RAW`：`sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))`。

本机开代理时注意：如果 `ALL_PROXY` 写成了 `socks://…`（httpx 只认 `socks5://`，且需要 `socksio`），
它会在**构造 `httpx.Client` 时就抛 `ValueError`**，跟走不走网络无关。而且环境里通常**同时有
`ALL_PROXY` 和 `all_proxy` 两个变量**——只 `unset` 一个不管用，httpx 读的是小写那个。
启动中心时这样绕开：

```bash
env -u ALL_PROXY -u all_proxy uvicorn center.main:app --port 8000
```

（保留 `HTTP(S)_PROXY` 的 `http://…` 形式即可，httpx 认它。）我们另外做了三处处理——
探针连局域网中心、看板连中心时按地址判定 `trust_env=False`（`settings.is_local_endpoint`）；
大模型客户端捕获该异常后不再重试，直接降级成模板报告。所以代理坏掉的表现是"报告是模板版"，
而不是服务起不来。

### 在 Windows 上跑

代码里没有 Linux 专有调用（`geteuid` / `fcntl` / `termios` / `/proc/` / `fork` 都查过，
`attack/common.py` 的 root 检查在 Windows 上自动跳过），四个进程都能起。差异只有这几条：

| 事项 | Linux | Windows |
|---|---|---|
| 抓包依赖 | libpcap | **装 Npcap**（安装时勾 "WinPcap API-compatible Mode"） |
| 抓包权限 | root 或 `CAP_NET_RAW` | **以管理员身份**开终端，没有 `setcap` 这条路 |
| 网卡名 | `eth0` / `wlan0` | `\Device\NPF_{GUID}`，见下 |
| 解释器 | `python3` | `python` |
| 虚拟环境 | `source .venv/bin/activate` | `.venv\Scripts\activate` |
| 环境变量 | `export K=V` | PowerShell `$env:K="V"`；cmd `set K=V` |

查网卡名（不传 `--iface` 时 scapy 用默认网卡，多数情况直接可用）：

```powershell
python -c "from scapy.all import get_if_list; print(*get_if_list(), sep='\n')"
python -m probe.sniffer --iface "\Device\NPF_{XXXXXXXX-...}"
```

代理变量在 PowerShell 里这样清：

```powershell
Remove-Item Env:ALL_PROXY -ErrorAction SilentlyContinue
Remove-Item Env:all_proxy -ErrorAction SilentlyContinue
```

`data/*.csv` 与 `data/raw/` 不进版本库（单文件最大 215 MB，超过 GitHub 的 100 MB 硬上限），
按第四节在本地重建；`models/artifacts/best_model.pkl` 随仓库提供，不想用就自己跑一次
`models/train.py`。`tools/replay_live.py` 在 Windows 上同样可用——它只用普通 socket，不要管理员权限。

---

## 六、在线路径的已知边界（为什么保留 M11 与大模型）

用真实抓包跑通整条链路后做的对照实验，细节在 `docs/architecture.md` 的
「在线路径实测：提取器与数据集的三处口径错配」。一句话版本：

**小模型学到的是这份数据集的判别边界，不是这类攻击的判别边界。**

- 数据集自己的行没有问题：类内时间留出集上 PortScan 召回 0.998、DoS Hulk 0.913，
  抽 300 条 PortScan 行 300/300 判对。
- 但按数据集形态手工构造的一条 DoS Hulk（6 个前向小包 + 6 个后向 1656 字节包、跨 85 s）
  仍被判 BENIGN 0.9999——数据集里的流量是"长流慢速"（中位 84.9 s / 6 包 / 0.16 包每秒），
  我们现场构造的是"短流突发"（0.1 s / 200 包 / 2010 包每秒）。
- 遇到没见过的形状时，小模型**既不报警也不报错**，这与跨天实验是同一条结论。

因此三层的分工是：小模型负责在已知形态里出类别与置信度（方法验证 / 演示），
**M11 规则引擎**负责线上兜底（判据是"同源短窗口内大量不同目的端口"这类与采集口径无关的行为），
大模型负责解释前两层说不清的流量。答辩时这条边界要主动讲，它比"准确率 0.99"更能说明我们懂自己在做什么。

另一处环境差异：`probe/sniffer.py --max-age` 默认 30 s，比数据集的 120 s 空闲超时短，
演示长流时务必调大，否则同一条流会被切成好几段、向量形态全变。

---

## 七、当前进度

- [x] 选题与任务书（草案 v1）
- [x] 系统架构图、小模型结构图、混合森林结构图、LLM 诊断管线图
- [x] M8 五模型训练与选型（24.5 万行真实样本；随机划分 → 类内按时间 → 前向滚动验证三档口径）
- [x] M8 跨天留出实验（`tools/cross_day_eval.py`，结论是开集失败，不谈泛化）
- [x] M1 / M2 探针：scapy 抓包 → 双向会话表 → 78 维 CICFlowMeter 口径特征
- [x] M3 / M6 中心服务：Token 鉴权上报、SQLite 落库、小模型推理、告警分级
- [x] M4 / M9 大模型层：DeepSeek 客户端 + BM25 协议知识库 + 结构化报告 + 看板助手，无 key 时降级为模板报告
- [x] M5 看板：实时总览 / 会话流水 / 告警 / 诊断报告 / 历史查询
- [x] M7 攻击复现（三支，带安全护栏，仅限授权实验网段）
- [x] M11 阈值规则引擎基线（与小模型同口径对照：单流规则 macro-F1 0.5795 vs 小模型 0.9719；
      窗口判据在小模型全判 BENIGN 的现场扫描流上仍能出告警）
- [x] `tools/replay_live.py`：无抓包权限时按节奏把数据集会话回放进中心（`--attack-every N` 控制攻击流比例，
      `--attack-every 0` 只发 BENIGN，`--dry-run` 只本地跑规则不发请求）
- [ ] M10 双探针联动演示
- [ ] 报告与答辩材料

自测：`python3 -m pytest`（59 条，合成数据为主，不依赖 CIC-IDS2017 原始文件）。
本机旧版 pytest 与 io 插件的 anyio 插件冲突，`pytest.ini` 里已 `-p no:anyio` 关掉它。
