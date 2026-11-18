# 本地数字取证保全包核验器

面向事故调查的**离线、纯标准库**数字取证保管链（chain of custody）核验器。
所有输入均为**合成数据**：证物是构造的短字节串、签名是模拟字符串、
摘要由 SHA-256 在本地计算，**不接触任何真实取证数据**。

运行环境：Windows 原生 Python 3.12、仅标准库、CPU。

---

## 1. 业务规则

### 1.1 证物与采集锚点

每件合成证物由一条**采集记录**固定：

* 证物内容的 SHA-256；
* 租户（tenant）、保管主体（custodian）；
* 采集机构与采集本地时刻；
* 采集摘要（collection digest）。

只有**已登记的采集记录**和**保全检查点**可作为锚点。保全检查点登记
`entry_global_ts`（入保全库的全局时刻，最终上界）以及一组
`accepted_terminal_digests`（允许作为链尾的确切交接摘要）。

### 1.2 交接记录

每条交接候选记录绑定：

* `prev_digest`：前一交接摘要（首跳指向采集摘要），必须对上**确切**摘要；
* 交出方 / 接收方：各自的模拟签名人、授权种类、本地签署时刻；
* `voucher_id`：物理交接凭单；
* `digest`：记录去掉 `digest` 字段后规范化 JSON 的 SHA-256。

候选记录可以**乱序、重复、分叉**：

* 乱序：不依赖数组顺序，按 `prev_digest` 建图；
* 重复：`handover_id` 与内容完全相同的重复登记被去重；内容冲突则拒绝；
* 分叉：同一前序摘要可挂多条候选，求解时择一。

记录要进入候选必须同时通过：

1. **完整性**：重算 SHA-256 与登记 `digest` 一致（伪造/篡改即排除）；
2. **授权/人员**：签名人已登记，且其具备该签名的授权种类；
3. **连接**：`prev_digest` 能对上某个采集锚点或另一条交接摘要。

### 1.3 物理凭单独占

同一个物理交接凭单（`voucher_id`）在全局解中**最多配给一件证物**。
一张凭单可被多个候选证物的承接记录引用，但最终解里不得冲突。

### 1.4 共享时钟校准

时间戳来自可能不一致的机构时钟。对每个机构 `i`，整包内只能选**一个整数秒
偏移** `o_i`，取值于给定闭区间 `[offset_min, offset_max]`。

事件 `e`（机构 `i`、本地读数 `t`）的全局时刻：

```
g_e = t + o_i
```

一条交接链上的事件（采集 → 交出签名 → 接收签名 → 下一交接 …）全局时刻必须
**非递减**；且每个签名全局时刻不晚于包截止时刻 `deadline` 与该证物
`entry_global_ts`。这保证双方签名都先于入保全库、交接时间非递减。

差约束统一写成 `x_v - x_u <= w` 的边，用 **Bellman-Ford 负环检测**判定
可行性：无负环即可校准，出现负环即该组链不可校准。

### 1.5 见证覆盖

每件证物的链上，必须有**至少两类不同机构**（`min_witness_kinds`，默认 2）
的独立人员分别给出覆盖见证。一个人员只登记在一个机构下，最多承担一类。
见证覆盖按每件证物链上实际出现的签名人所属机构去重统计。

### 1.6 求解目标与决胜顺序

对最多 8 件证物、60 条候选记录求一个全局合法解，按以下顺序取最优：

1. **最少不同出库交接项数**（授权种类含 `outbound` 的不同交接记录数）；
2. 再按**证物 ID 与交接 ID 序列**比较（字典序）；
3. 然后选**字典序最小的可行全局时刻**：先取机构 ID 字典序最小的可行偏移
   向量，再在固定偏移下逐事件取满足非递减与上界的最小全局时刻。

---

## 2. 目录结构

```
solution/
  __init__.py
  __main__.py     # CLI 入口（python -m solution）
  errors.py       # 错误码
  model.py        # 输入解析、校验、SHA-256 完整性
  calibration.py  # 链枚举 + 差约束（Bellman-Ford）
  solver.py       # 全局搜索、见证判定、三级决胜、无解分类
  report.py       # result.json 序列化
tools/
  generate_cases.py  # 确定性合成 cases.json
  brute_force.py     # 独立组合穷举校验器（交叉验证用）
tests/
  test_solver.py
  test_integrity.py
  test_calibration.py
  test_brute_force.py
  test_cli.py
cases.json        # 12 个可重放合成用例
result.json       # 对 cases.json 的实测求解结果
```

---

## 3. 输入 / 输出

### 3.1 生成输入

```
python -I tools/generate_cases.py
```

确定性地重写 `cases.json`（无随机源，可任意重放）。

### 3.2 运行求解

```
python -m solution --input cases.json --output result.json
```

> 在开启隔离模式的环境中，`-I` 会忽略 `PYTHONPATH`，可在仓库根目录用
> `sys.path` 引导运行，测试 `tests/test_cli.py` 即采用该方式。

输入支持两种形态：

* 单个保全包对象；
* 带 `"cases": [...]` 的多包文件，对每个包分别求解，结果按序放入 `results`。

### 3.3 输入字段（单个包）

| 字段 | 含义 |
| --- | --- |
| `case_id` | 用例 ID |
| `deadline` | 包级全局截止时刻（整数秒） |
| `min_witness_kinds` | 每件证物所需的最少见证机构种类 |
| `institutions[]` | 机构及其偏移闭区间 `offset_min/offset_max` |
| `persons[]` | 人员、所属机构、授权种类集合 |
| `evidences[]` | 证物、采集记录、保全检查点与承接摘要白名单 |
| `handovers[]` | 交接候选（含 `digest`、`prev_digest`、凭单、双签名） |

### 3.4 输出字段

成功（`status = "SAT"`）的 `solution`：

* `distinct_outbound_count` / `distinct_outbound_handover_ids`：不同出库项；
* `institution_offsets`：每个机构最终选定的整数秒偏移；
* `evidences[]`：每件证物的回链，含采集、逐跳交接、每签名的本地/全局时刻、
  `effective_global_ts`（双签名全局时刻的较大者）、链尾摘要、见证机构分布。

失败（`status = "UNSAT"`）的 `error`：错误码与子原因，见下节。

---

## 4. 错误码

| 错误码 | 含义 | `detail` 子原因 |
| --- | --- | --- |
| `EVIDENCE_UNCALIBRATABLE` | 单件不可校准 | `evidence_reasons` 逐证物给 `no_structural_chain`（无锚点链）或 `clock_not_calibratable`（差约束无解） |
| `GLOBAL_VOUCHER_CONFLICT` | 全局交接占用冲突 | `voucher_occupancy_conflict`（物理凭单无法互不冲突地分配）或 `joint_clock_calibration_conflict`（凭单可分配，但跨证物共享时钟联合无解） |
| `WITNESS_INSUFFICIENT` | 见证不足 | 凭单与时钟均可行，但至少一件证物的见证机构种类少于 `min_witness_kinds` |
| `INVALID_CASE` | 输入结构非法 | 解析期错误信息 |
| `PACKAGE_TOO_LARGE` | 超过保护性搜索上限 | 候选链/叶节点超界 |

无解分类按优先级判定：先单件可校准性，再凭单/时钟的全局可行性，最后见证。

---

## 5. 实测结果

命令：

```
python -m unittest discover -s tests -v
```

实测（Windows 11、Python 3.12.8、CPU）：**32 个测试全部通过**。
`cases.json` 中 12 个合成用例的求解结论：

| 用例 | 结论 | 关键断言 |
| --- | --- | --- |
| `basic_sat` | SAT | 链 H1→H2，偏移取区间下界，全局时刻非递减，1 个出库项 |
| `fork_tie` | SAT | 等长出库数下按交接 ID 选 H2A（而非 H2B） |
| `voucher_coupling` | SAT | 最短链占用他物唯一凭单，被迫选 E1 长链，凭单互不重叠 |
| `clock_reversal` | SAT | 表面 200>150 时间反转，经偏移校准后全局非递减 |
| `joint_clock_conflict` | UNSAT | `GLOBAL_VOUCHER_CONFLICT / joint_clock_calibration_conflict` |
| `voucher_conflict` | UNSAT | `GLOBAL_VOUCHER_CONFLICT / voucher_occupancy_conflict` |
| `witness_insufficient` | UNSAT | `WITNESS_INSUFFICIENT`（签名人只属一类机构） |
| `repeated_witness` | UNSAT | `WITNESS_INSUFFICIENT`（同一人员重复，种类仍不足） |
| `forged_fork` | SAT | 伪造分叉摘要核验失败被排除，仅合法分叉可用 |
| `uncalibratable` | UNSAT | `EVIDENCE_UNCALIBRATABLE`，逐证物区分无链/不可校准 |
| `out_of_order_dup` | SAT | 乱序 + 重复候选去重后正常求解 |
| `brute_force_oracle` | SAT | 与独立穷举器逐字段一致 |

独立交叉验证：`tools/brute_force.py` 用完全独立的笛卡尔积 + 全偏移枚举实现，
对全部 12 例在**状态、链选择、出库数、扁平化全局时刻、错误子原因**上与主求解器
逐项一致（`tests/test_brute_force.py` 固化该断言）。

规模实测：8 件证物、60 条候选记录的高分叉合成包，主求解器约 2.6 秒得解。

---

## 6. 设计要点

* 链枚举只在“通过完整性/授权/连接”的记录上按 `prev_digest` 建图，并带环防御；
* 时钟校准是纯差约束系统，机构区间用虚拟源的上/下界边表达，负环即不可行；
* 全局回溯按“候选链少的证物优先”排序，并在每一步用联合差约束提前剪枝；
* 三级无解分类与独立穷举器共用同一判定口径，避免误分类；
* 全部摘要、签名、证物内容均为本地合成，离线可重放。
