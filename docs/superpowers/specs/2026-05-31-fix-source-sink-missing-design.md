# Fix: Source/Sink 列表不完整导致漏报

**日期**：2026-05-31  
**文件**：`iotreaper.py`，函数 `run_stage_danger()`  
**范围**：最小改动，仅修 `iotreaper.py`，不动 Java 脚本、config.ini、infer 阶段

---

## 背景

经过对 `CH22_30v2` 运行结果的调试，发现 `frmL7ImForm`（地址 0x46440）中的
`sprintf(s, "im.asp?page=%s", v6)` 栈溢出漏洞未被检出。根因有两个，均在
`run_stage_danger()` 中：

1. **Bug 1**：LLM sink 阶段有结果时，`config.ini [VulFunction]` 中的
   buffer overflow sink（`sprintf`、`strcat`、`popen`、`sscanf`、`memcpy`）
   被完全丢弃，只强制保留了 `system` 和 `strcpy`。
   `DangerFlowAnalyzer.java` 拿到的 sink 列表缺少 `sprintf`，
   调用图里永远不会出现以 `sprintf` 为 child 的节点。

2. **Bug 2**：`parsed_sources` 只取 LLM 识别结果（`config.IoTReaperConfig.source_point`），
   未合并 `config.ini [SourceFunction]`（含 `sub_28B84`）。
   `DangerFlowAnalyzer.java` 找不到 `frmL7ImForm` 为 entry function，
   即使 Bug 1 修好，该函数也不会进入调用图。

两个 bug 叠加，导致整条路径
`sub_28B84 → frmL7ImForm → sprintf` 在 danger 阶段完全不可见，
infer 阶段也就无从发现。

---

## 设计

### Bug 1 修复：sink 列表强制包含 config.ini 全部项

**位置**：`iotreaper.py` `run_stage_danger()`，现行第 268–273 行附近

**现行逻辑**：
```python
sink_data = "['system','strcat','sprintf','popen','strcpy']"
if len(config.IoTReaperConfig.sink_point) != 0:
    config.IoTReaperConfig.sink_point.append("system")
    config.IoTReaperConfig.sink_point.append("strcpy")
    sink_data = str(config.IoTReaperConfig.sink_point)
upsert_ProjectInfo_data(tag="sink", data=sink_data)
```

**修复后逻辑**：
```python
sink_data = "['system','strcat','sprintf','popen','strcpy']"
if len(config.IoTReaperConfig.sink_point) != 0:
    # 从 config.ini [VulFunction] 读出所有 sink，追加缺失项
    vul_funcs = config.IoTReaperConfig.config.get("VulFunction", {})
    config_sinks = []
    for val in vul_funcs.values():
        # 跳过 "param" 键（json 格式，不是函数名列表）
        try:
            import json as _json
            _json.loads(val)
            continue
        except Exception:
            pass
        config_sinks += [s.strip() for s in val.split(",") if s.strip()]
    for s in config_sinks:
        if s not in config.IoTReaperConfig.sink_point:
            config.IoTReaperConfig.sink_point.append(s)
    sink_data = str(config.IoTReaperConfig.sink_point)
upsert_ProjectInfo_data(tag="sink", data=sink_data)
```

**效果**：
- LLM 无结果时（`sink_point == []`）：兜底字符串不变
- LLM 有结果时：config.ini 里的所有 sink 函数名均被追加，不再丢失
- config.ini 是唯一真相来源，新增 sink 只改配置

---

### Bug 2 修复：source 写入 DB 前合并 config.ini `[SourceFunction]`

**位置**：`iotreaper.py` `run_stage_danger()`，现行第 260–264 行附近

**现行逻辑**：
```python
if config.IoTReaperConfig.source_point != []:
    parsed_sources = config.IoTReaperConfig.source_point
upsert_ProjectInfo_data(tag="source", data=str(parsed_sources))
```

**修复后逻辑**：
```python
if config.IoTReaperConfig.source_point != []:
    parsed_sources = config.IoTReaperConfig.source_point
# 合并 config.ini [SourceFunction]，与 infer 阶段保持一致
if "SourceFunction" in config.IoTReaperConfig.config:
    for val in config.IoTReaperConfig.config["SourceFunction"].values():
        for s in val.split(","):
            s = s.strip()
            if s and s not in parsed_sources:
                parsed_sources.append(s)
upsert_ProjectInfo_data(tag="source", data=str(parsed_sources))
```

**效果**：
- SQLite `source` 字段变为 LLM 结果 ∪ config.ini `[SourceFunction]`
- `DangerFlowAnalyzer.java` 拿到完整 source 列表，`sub_28B84` 进入其中
- `frmL7ImForm`（调用 `sub_28B84`）被识别为 entry function，进入调用图
- `infer` 阶段的合并逻辑不变（本来就正确）

---

## 不改动的部分

| 文件 | 原因 |
|------|------|
| `scripts/DangerFlowAnalyzer.java` | 读 DB 的逻辑不变，DB 内容修正后自动受益 |
| `core/simple_path_finder.py` | infer 阶段合并逻辑已正确，不动 |
| `config/config.ini` | 无需改动，是真相来源 |
| `core/taint_parser.py` | 不涉及 |
| `run_stage_infer()` | 不涉及 |

---

## 验证标准

修复后重跑 `danger` 阶段，检查：

1. SQLite `project_info` 表中 `source` 字段包含 `sub_28B84`
2. SQLite `project_info` 表中 `sink` 字段包含 `sprintf`
3. `parent_child_calls.json` 中出现以 `frmL7ImForm` 为 parent、`sprintf` 为 child 的节点
4. `vul_result.txt` 中出现包含 `frmL7ImForm` 的漏洞报告
