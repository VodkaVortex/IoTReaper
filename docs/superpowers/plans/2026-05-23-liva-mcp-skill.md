# LIVA-MCP Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace LIVA's Windows IDA HTTP service with local IDA MCP tool calls, packaged as a Claude Code skill that orchestrates the full 7-stage pipeline.

**Architecture:** Python handles Ghidra / SQLite / Neo4j / LLM stages unchanged. Claude (as skill runner) calls `mcp__ida-mcp__*` tools directly in place of the Windows HTTP service. A thin Python bridge (`IDAMCPBridge`) writes request manifests before IDA steps and reads MCP-written result files after. The skill file is the top-level orchestrator that sequences Python sub-stages and MCP calls.

**Tech Stack:** Python 3.11, IDA MCP (`mcp__ida-mcp__decompile`, `lookup_funcs`, `list_sessions`), SQLAlchemy/SQLite, Neo4j 5.x, Ghidra headless, OpenAI-compat API (deepseek-v3 + fine-tuned Liva model)

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `core/idanet/IDAMCPBridge.py` | Write request manifests / read MCP result files |
| Modify | `liva.py` | Add `--backend mcp` flag; add sub-stages `source-ghidra`, `source-llm`, `sink-ghidra`, `sink-llm`, `danger-ghidra` |
| Modify | `core/danger_func_analyzer.py` | Add `run_dangerfunc_ghidra_only()` that stops before IDA HTTP call |
| Create | `~/.claude/skills/LIVA-MCP/skill.md` | The skill: full pipeline orchestration with MCP decompile steps |
| Create | `tests/test_ida_mcp_bridge.py` | Unit tests for bridge read/write helpers |

---

## Stage Split Design

The key insight: Python stages that call IDA must be split so Claude can inject MCP results between them.

```
Original: source  = ghidra + ida_http + llm   (one function)
MCP mode: source-ghidra  →  [Claude MCP]  →  source-llm

Original: sink    = ghidra + ida_http + llm
MCP mode: sink-ghidra    →  [Claude MCP]  →  sink-llm

Original: danger  = ghidra + ida_http
MCP mode: danger-ghidra  →  [Claude MCP writes parent_child_calls_ida_decompile.json]
          (danger-postprocess is just the existing danger interaction prompt, now reads the MCP file)
```

`--backend http` (default) keeps the original combined stages unchanged.

---

## Task 1: Create `core/idanet/IDAMCPBridge.py`

**Files:**
- Create: `core/idanet/IDAMCPBridge.py`
- Test: `tests/test_ida_mcp_bridge.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ida_mcp_bridge.py
import json, pytest
from pathlib import Path
from core.idanet.IDAMCPBridge import IDAMCPBridge

@pytest.fixture
def bridge(tmp_path):
    return IDAMCPBridge(tmp_path)

def test_write_source_request_creates_file(bridge, tmp_path):
    bridge.write_source_decompile_request(
        funcs_by_lib={"libnvram.so": ["nvram_get", "nvram_set"]},
        file_mapping={"libnvram.so": "/result/dev/proj/iot_file/libnvram.so"},
    )
    req = json.loads((tmp_path / "mcp_source_decompile_request.json").read_text())
    assert req["type"] == "source_decompile"
    assert req["funcs_by_lib"]["libnvram.so"] == ["nvram_get", "nvram_set"]

def test_read_source_result_raises_when_missing(bridge):
    with pytest.raises(FileNotFoundError, match="mcp_source_decompile_result.json"):
        bridge.read_source_decompile_result()

def test_read_source_result_returns_dict(bridge, tmp_path):
    payload = {
        "libnvram.so": {
            "status": 200,
            "resp": {"nvram_get": {"code": "char *nvram_get(char *key) { ... }", "inlined_from": []}}
        }
    }
    (tmp_path / "mcp_source_decompile_result.json").write_text(json.dumps(payload))
    result = bridge.read_source_decompile_result()
    assert result["libnvram.so"]["resp"]["nvram_get"]["code"].startswith("char *nvram_get")

def test_write_danger_request_extracts_addresses(bridge, tmp_path):
    calls = {"data": [
        {"parent_name": "foo", "parent_address": "0x1234", "children": []},
        {"parent_name": "bar", "parent_address": "0x5678", "children": []},
        {"parent_name": "dup", "parent_address": "0x1234", "children": []},  # duplicate
    ]}
    calls_path = tmp_path / "parent_child_calls.json"
    calls_path.write_text(json.dumps(calls))
    bridge.write_danger_decompile_request(calls_path)
    req = json.loads((tmp_path / "mcp_danger_decompile_request.json").read_text())
    assert req["type"] == "danger_decompile"
    assert req["addresses"] == ["0x1234", "0x5678"]   # deduped
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda activate Liva
pytest tests/test_ida_mcp_bridge.py -v
# Expected: ImportError — core/idanet/IDAMCPBridge.py does not exist yet
```

- [ ] **Step 3: Implement `core/idanet/IDAMCPBridge.py`**

```python
# core/idanet/IDAMCPBridge.py
import json
from pathlib import Path
from typing import Dict, List, Any


class IDAMCPBridge:
    """
    Protocol:
      Python writes REQUEST → Claude calls IDA MCP → Claude writes RESULT → Python reads RESULT
    """

    SOURCE_REQUEST = "mcp_source_decompile_request.json"
    SOURCE_RESULT  = "mcp_source_decompile_result.json"
    SINK_REQUEST   = "mcp_sink_decompile_request.json"
    SINK_RESULT    = "mcp_sink_decompile_result.json"
    DANGER_REQUEST = "mcp_danger_decompile_request.json"

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)

    # ── Source ──────────────────────────────────────────────────────

    def write_source_decompile_request(
        self,
        funcs_by_lib: Dict[str, List[str]],
        file_mapping: Dict[str, str],
    ) -> Path:
        payload = {
            "type": "source_decompile",
            "funcs_by_lib": funcs_by_lib,
            "file_mapping": file_mapping,
        }
        return self._write(self.SOURCE_REQUEST, payload)

    def read_source_decompile_result(self) -> Dict[str, Any]:
        """
        Returns same shape as WindowsIDAClient.send_multiple_libs():
        {
          "libname.so": {
            "status": 200,
            "resp": {
              "func_name": {"code": "...", "inlined_from": [...]}
            }
          }
        }
        """
        return self._read(self.SOURCE_RESULT)

    # ── Sink ─────────────────────────────────────────────────────────

    def write_sink_decompile_request(
        self,
        funcs_by_lib: Dict[str, List[str]],
        file_mapping: Dict[str, str],
        chains_by_lib: Dict[str, List[List[str]]],
    ) -> Path:
        payload = {
            "type": "sink_decompile",
            "funcs_by_lib": funcs_by_lib,
            "file_mapping": file_mapping,
            "chains_by_lib": chains_by_lib,
        }
        return self._write(self.SINK_REQUEST, payload)

    def read_sink_decompile_result(self) -> Dict[str, Any]:
        return self._read(self.SINK_RESULT)

    # ── Danger ───────────────────────────────────────────────────────

    def write_danger_decompile_request(self, parent_child_calls_path: Path) -> Path:
        """
        Reads parent_child_calls.json, extracts unique parent_address values,
        and writes a request manifest for Claude to call mcp__ida-mcp__decompile.
        """
        root = json.loads(parent_child_calls_path.read_text(encoding="utf-8"))
        seen: set = set()
        addresses: List[str] = []
        for item in root.get("data", []):
            pa = item.get("parent_address", "")
            if isinstance(pa, str) and pa.strip() and pa not in seen:
                addresses.append(pa.strip())
                seen.add(pa.strip())

        payload = {"type": "danger_decompile", "addresses": addresses}
        return self._write(self.DANGER_REQUEST, payload)

    # ── Internal ─────────────────────────────────────────────────────

    def _write(self, filename: str, payload: dict) -> Path:
        out = self.base_dir / filename
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return out

    def _read(self, filename: str) -> Dict[str, Any]:
        path = self.base_dir / filename
        if not path.exists():
            raise FileNotFoundError(
                f"{path}\n"
                "Skill must call IDA MCP tools and write this file before Python can continue."
            )
        return json.loads(path.read_text(encoding="utf-8"))
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_ida_mcp_bridge.py -v
# Expected: 5 tests PASSED
```

- [ ] **Step 5: Commit**

```bash
git add core/idanet/IDAMCPBridge.py tests/test_ida_mcp_bridge.py
git commit -m "feat: add IDAMCPBridge for request/result manifest exchange"
```

---

## Task 2: Split source stage into `source-ghidra` and `source-llm`

**Files:**
- Modify: `liva.py:57-118` (run_stage_source)

- [ ] **Step 1: Add `run_stage_source_ghidra()` function**

Insert after `run_stage_source()` in `liva.py`:

```python
def run_stage_source_ghidra():
    """
    Sub-stage: Run Ghidra analysis, build funcs_by_lib, write MCP request manifest.
    Stops before IDA HTTP call. Run source-llm after Claude writes the MCP result file.
    """
    try:
        from core.idanet.IDAMCPBridge import IDAMCPBridge
        from pathlib import Path

        source_identifier = SourceIdentifier()
        source_identifier.run_sourceidentifier_batch_analysis()
        source_identifier.load()

        res = source_identifier.parse_call_report_file()
        sorted_items = sorted(res.items(), key=lambda x: x[1], reverse=True)
        top_quarter_count = max(1, len(sorted_items) // 2)
        top_funcs = [name for name, count in sorted_items[:top_quarter_count]]
        grouped = source_identifier.find_by_lib_grouped(top_funcs, exact=True)
        source_identifier.pretty_print(grouped)

        funcs_by_lib = grouped
        file_mapping = {}
        for binary in grouped:
            file_mapping[binary] = (
                f"result/{config.LivaConfig.project_path}"
                f"/{config.LivaConfig.main_project_name}/iot_file/{binary}"
            )

        base_dir = Path(
            f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}"
        )
        bridge = IDAMCPBridge(base_dir)
        req_path = bridge.write_source_decompile_request(funcs_by_lib, file_mapping)
        print(f"[SOURCE-GHIDRA] MCP request written → {req_path}")
        print("[SOURCE-GHIDRA] Now run the LIVA-MCP skill (or manually call IDA MCP),")
        print(f"  then write result to: {base_dir / IDAMCPBridge.SOURCE_RESULT}")
        print("  Format: {libname: {status:200, resp: {func_name: {code:'...'}}}}")

    except Exception:
        logging.getLogger().exception("[SOURCE-GHIDRA] Stage failed")
        raise


def run_stage_source_llm():
    """
    Sub-stage: Read MCP-written source decompile result, send to LLM, extract source points.
    Requires mcp_source_decompile_result.json to exist (written by Claude via IDA MCP).
    """
    try:
        from core.idanet.IDAMCPBridge import IDAMCPBridge
        from pathlib import Path

        base_dir = Path(
            f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}"
        )
        bridge = IDAMCPBridge(base_dir)
        batch_resp = bridge.read_source_decompile_result()

        llm_source_send = ""
        for i in batch_resp:
            for j in batch_resp[i]['resp']:
                current_code = batch_resp[i]['resp'][j]["code"]
                if 'inlined_from' in batch_resp[i]['resp'][j]:
                    inlined_codes = [
                        callee["code"]
                        for callee in batch_resp[i]['resp'][j]["inlined_from"]
                    ]
                    llm_source_send += (
                        current_code + "\n" + "\n".join(inlined_codes) + "\n-------------------------------"
                    )
                else:
                    llm_source_send += current_code + "\n-------------------------------"

        chatbot = Chatbot(config_file="config/config.ini", chat_type="source")
        response = chatbot.chat(llm_source_send)
        if isinstance(response, bytes):
            source_point = parse_funcnames(response.decode("utf-8", errors="ignore"))
            config.LivaConfig.source_point = source_point
        else:
            print(response)

    except Exception:
        logging.getLogger().exception("[SOURCE-LLM] Stage failed")
        raise
```

- [ ] **Step 2: Add sub-stages to the stage registry in `liva.py`**

Find `RUN_ORDER = ["elf", "source", "sink", "danger", "taint", "neo4j", "infer"]` at line 419 and replace:

```python
RUN_ORDER = [
    "elf",
    "source", "source-ghidra", "source-llm",
    "sink",   "sink-ghidra",   "sink-llm",
    "danger", "danger-ghidra",
    "taint", "neo4j", "infer",
]
```

- [ ] **Step 3: Add dispatch cases in the main stage loop**

In the `for stage in stages_to_run:` loop, add after the `elif stage == "source":` block:

```python
elif stage == "source-ghidra":
    run_with_timer("source-ghidra", run_stage_source_ghidra)

elif stage == "source-llm":
    run_with_timer("source-llm", run_stage_source_llm)
```

- [ ] **Step 4: Verify the help text lists new stages**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda activate Liva
python3 liva.py --help 2>&1 | head -20
# Expected: no crash; stages list appears
python3 liva.py /dev/null /tmp DevTest --stages source-ghidra --dry-run
# Expected: [Plan] Stages to run (in order): source-ghidra
```

- [ ] **Step 5: Commit**

```bash
git add liva.py
git commit -m "feat: split source stage into source-ghidra and source-llm sub-stages"
```

---

## Task 3: Split sink stage into `sink-ghidra` and `sink-llm`

**Files:**
- Modify: `liva.py:120-185` (run_stage_sink)

- [ ] **Step 1: Add `run_stage_sink_ghidra()` and `run_stage_sink_llm()` to `liva.py`**

Insert after `run_stage_sink()`:

```python
def run_stage_sink_ghidra():
    """
    Sub-stage: Run Ghidra sink analysis, write MCP request manifest.
    Stops before IDA HTTP call.
    """
    try:
        from core.idanet.IDAMCPBridge import IDAMCPBridge
        from pathlib import Path

        identifier = SinkIdentifier()
        identifier.run_sink_batch_analysis()
        parsed_results = identifier.load_results_from_sqlite()
        funcs_by_lib, file_mapping, chains_by_lib = (
            identifier.build_funcs_files_and_chains_from_parsed_results(
                parsed_results,
                base_dir=(
                    f"result/{config.LivaConfig.project_path}"
                    f"/{config.LivaConfig.main_project_name}/iot_file/"
                ),
                verbose=True,
            )
        )

        base_dir = Path(
            f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}"
        )
        bridge = IDAMCPBridge(base_dir)
        req_path = bridge.write_sink_decompile_request(funcs_by_lib, file_mapping, chains_by_lib)
        print(f"[SINK-GHIDRA] MCP request written → {req_path}")
        print(f"  Write result to: {base_dir / IDAMCPBridge.SINK_RESULT}")
        print("  Format: same as source result (libname → resp → func_name → code)")

    except Exception:
        logging.getLogger().exception("[SINK-GHIDRA] Stage failed")
        raise


def run_stage_sink_llm():
    """
    Sub-stage: Read MCP sink result, run LLM chain analysis, set sink_point.
    """
    try:
        from core.idanet.IDAMCPBridge import IDAMCPBridge
        from pathlib import Path

        identifier = SinkIdentifier()
        parsed_results = identifier.load_results_from_sqlite()
        _, _, chains_by_lib = identifier.build_funcs_files_and_chains_from_parsed_results(
            parsed_results,
            base_dir=(
                f"result/{config.LivaConfig.project_path}"
                f"/{config.LivaConfig.main_project_name}/iot_file/"
            ),
            verbose=False,
        )

        base_dir = Path(
            f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}"
        )
        bridge = IDAMCPBridge(base_dir)
        batch_resp = bridge.read_sink_decompile_result()

        sink: list = []
        added_chains: set = set()

        for item in chains_by_lib:
            if len(chains_by_lib[item]) == 0:
                continue
            for func_list in chains_by_lib[item]:
                chain = ""
                code = ""
                first_func = func_list[0]
                for func in func_list:
                    chain += "->" + func
                    func_data = batch_resp.get(item, {}).get("resp", {}).get(func, {})
                    code += "--------------------------\n" + func_data.get("code", "")
                if chain in added_chains:
                    continue
                added_chains.add(chain)

                send_llm = "Call chains: " + chain + "\n" + "Code: \n" + code
                chatbot = Chatbot(config_file="config/config.ini", chat_type="sink")
                response = chatbot.chat(send_llm)
                print(chain, response)
                if isinstance(response, bytes) and b"Yes" in response:
                    sink.append(first_func)

        config.LivaConfig.sink_point = sink

    except Exception:
        logging.getLogger().exception("[SINK-LLM] Stage failed")
        raise
```

- [ ] **Step 2: Add dispatch cases in main loop**

```python
elif stage == "sink-ghidra":
    run_with_timer("sink-ghidra", run_stage_sink_ghidra)

elif stage == "sink-llm":
    run_with_timer("sink-llm", run_stage_sink_llm)
```

- [ ] **Step 3: Dry-run test**

```bash
python3 liva.py /dev/null /tmp DevTest --stages sink-ghidra,sink-llm --dry-run
# Expected: [Plan] Stages to run (in order): sink-ghidra -> sink-llm
```

- [ ] **Step 4: Commit**

```bash
git add liva.py
git commit -m "feat: split sink stage into sink-ghidra and sink-llm sub-stages"
```

---

## Task 4: Add `danger-ghidra` sub-stage

**Files:**
- Modify: `core/danger_func_analyzer.py` (add `run_dangerfunc_ghidra_only()`)
- Modify: `liva.py` (add `run_stage_danger_ghidra()`)

- [ ] **Step 1: Add `run_dangerfunc_ghidra_only()` to `DangerFuncAnalyzer`**

In [core/danger_func_analyzer.py](core/danger_func_analyzer.py), read the `build_dangerfunc_job()` and `run_dangerfunc_batch_analysis()` methods, then add after them:

```python
def run_dangerfunc_ghidra_only(self) -> Path:
    """
    Run Ghidra danger-func analysis and write parent_child_calls.json.
    Stops before calling IDA HTTP service.
    Callers should use IDAMCPBridge.write_danger_decompile_request() next,
    then have Claude call mcp__ida-mcp__decompile, then read results.
    """
    from core.idanet.IDAMCPBridge import IDAMCPBridge

    # Step 1: Ghidra analysis → writes parent_child_calls.json
    self.run_dangerfunc_batch_analysis()

    # Step 2: Write MCP request manifest (extracts addresses from parent_child_calls.json)
    base_dir = Path(
        f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}"
    )
    calls_path = base_dir / "parent_child_calls.json"
    if not calls_path.exists():
        raise FileNotFoundError(f"Ghidra did not produce {calls_path}")

    bridge = IDAMCPBridge(base_dir)
    req_path = bridge.write_danger_decompile_request(calls_path)
    self.logger.info(f"[DANGER-GHIDRA] MCP request written → {req_path}")
    print(f"[DANGER-GHIDRA] Now call IDA MCP to decompile each address.")
    print(f"  Request file: {req_path}")
    print(f"  Write result to: {base_dir / 'parent_child_calls_ida_decompile.json'}")
    print(
        "  Format: {\"data\": [{\"parent_name\":\"...\", \"parent_address\":\"0x...\","
        " \"decompiled_c\":\"...\", \"children\":[...], \"child_names\":[...]}, ...]}"
    )
    return req_path
```

- [ ] **Step 2: Add `run_stage_danger_ghidra()` to `liva.py`**

```python
def run_stage_danger_ghidra():
    """
    Sub-stage: Run Ghidra danger analysis only, write MCP decompile request.
    After this, Claude calls IDA MCP and writes parent_child_calls_ida_decompile.json.
    """
    try:
        reverse_config = config.LivaConfig.config["Reverse"]
        danger_func = DangerFuncAnalyzer(
            service_url=reverse_config["ida_url"],
            token=reverse_config["token"],
        )

        # Save source/sink to SQLite first (same as run_stage_danger preamble)
        parsed_sources = config.LivaConfig.source_point or ['getenv|0x0040ccf0']
        print("SourcePoint:", parsed_sources)
        upsert_ProjectInfo_data(tag="source", data=str(parsed_sources))

        sink_data = "['system','strcat','sprintf','popen','strcpy']"
        if len(config.LivaConfig.sink_point) != 0:
            config.LivaConfig.sink_point.extend(["system", "strcpy"])
            sink_data = str(config.LivaConfig.sink_point)
        upsert_ProjectInfo_data(tag="sink", data=sink_data)

        danger_func.run_dangerfunc_ghidra_only()

    except Exception:
        logging.getLogger().exception("[DANGER-GHIDRA] Stage failed")
        raise
```

- [ ] **Step 3: Add dispatch case in main loop**

```python
elif stage == "danger-ghidra":
    run_with_timer("danger-ghidra", run_stage_danger_ghidra)
```

- [ ] **Step 4: Dry-run test**

```bash
python3 liva.py /dev/null /tmp DevTest --stages danger-ghidra --dry-run
# Expected: [Plan] Stages to run (in order): danger-ghidra
```

- [ ] **Step 5: Commit**

```bash
git add core/danger_func_analyzer.py liva.py
git commit -m "feat: add danger-ghidra sub-stage and DangerFuncAnalyzer.run_dangerfunc_ghidra_only()"
```

---

## Task 5: Write the skill file `~/.claude/skills/LIVA-MCP/skill.md`

**Files:**
- Create: `~/.claude/skills/LIVA-MCP/skill.md`

- [ ] **Step 1: Create the skill directory**

```bash
mkdir -p ~/.claude/skills/LIVA-MCP
```

- [ ] **Step 2: Write the skill file**

```bash
cat > ~/.claude/skills/LIVA-MCP/skill.md << 'SKILL_EOF'
```

Full skill file content — write exactly this to `~/.claude/skills/LIVA-MCP/skill.md`:

```markdown
# LIVA-MCP: IoT Firmware Vulnerability Mining Skill

## Trigger
Use this skill when the user asks to analyze IoT firmware for vulnerabilities using LIVA,
or says phrases like "run LIVA", "analyze firmware", "find vulnerabilities in binary".

## Overview
LIVA is a 7-stage pipeline that mines vulnerabilities in IoT firmware ELF binaries.
This skill runs the pipeline using local IDA MCP instead of the Windows HTTP IDA service.

**Announce at start:** "I'm using the LIVA-MCP skill to analyze firmware for vulnerabilities."

## Prerequisites (verify before starting)

1. **IDA Pro sessions open** for the target binary AND its dependency libraries.
   - Call `mcp__ida-mcp__list_sessions()` to list open sessions.
   - Note the `session_id` for each loaded binary. You will need them in Stage 3 and 4.

2. **Python environment** activated:
   ```bash
   conda activate Liva
   cd /path/to/LIVA-main
   ```

3. **Ghidra installed** at `./ghidra/support/analyzeHeadless` (relative to LIVA root).

4. **Neo4j running** at the URI in `config/config.ini [Neo4j]`.

5. **Fine-tuned Liva model running** at the endpoint in `config/config.ini [Fine-tuning]`.

## Input Parameters

Ask the user for these if not provided:
- `BINARY` — absolute path to the main ELF binary (e.g. `/extracted/jhttpd`)
- `SEARCH_DIR` — directory containing all firmware files (e.g. `/extracted/`)
- `DEVICE` — device label used as result directory name (e.g. `Dlink-DI8300`)

## Pipeline Execution

### Stage 0: Verify IDA Sessions

```python
# Call this MCP tool to see what's open
mcp__ida-mcp__list_sessions()
```

Note the `session_id` values. Match each session to a library name by reading the
session's loaded filename. You need one session per library that source/sink will decompile.

If no sessions are open: tell the user to open the firmware binary (and key libraries like
libnvram.so, libshared.so) in IDA Pro before continuing.

### Stage 1: ELF Parsing

```bash
python3 liva.py {BINARY} {SEARCH_DIR} {DEVICE} --stages elf
```

Expected output: `result/{DEVICE}/` directory created with library copies and `ghidra_analyze_res.db`.

### Stage 2: Source — Ghidra Analysis

```bash
python3 liva.py {BINARY} {SEARCH_DIR} {DEVICE} --stages source-ghidra
```

Expected output: `result/{DEVICE}/{PROJECT}/mcp_source_decompile_request.json`

The request file contains:
```json
{
  "type": "source_decompile",
  "funcs_by_lib": {"libnvram.so": ["nvram_get", ...], ...},
  "file_mapping": {"libnvram.so": "result/.../iot_file/libnvram.so"}
}
```

### Stage 3: Source — IDA MCP Decompilation

For each library in `funcs_by_lib`:

1. Find the IDA session for that library (match binary name from `list_sessions()`).
2. For each function name in `funcs_by_lib[libname]`:
   a. Call `mcp__ida-mcp__lookup_funcs(session_id=SID, queries=["func_name"])` to get the address.
   b. Call `mcp__ida-mcp__decompile(session_id=SID, addr="0xADDR")` to get pseudocode.
3. Collect results and write `mcp_source_decompile_result.json`:

```json
{
  "libnvram.so": {
    "status": 200,
    "resp": {
      "nvram_get": {
        "code": "<decompiled C pseudocode string>",
        "inlined_from": []
      }
    }
  }
}
```

Write this file to: `result/{DEVICE}/{PROJECT}/mcp_source_decompile_result.json`

### Stage 4: Source — LLM Classification

```bash
python3 liva.py {BINARY} {SEARCH_DIR} {DEVICE} --stages source-llm
```

This reads `mcp_source_decompile_result.json`, sends code to LLM, and identifies source functions.

### Stage 5: Sink — Ghidra Analysis

```bash
python3 liva.py {BINARY} {SEARCH_DIR} {DEVICE} --stages sink-ghidra
```

Expected output: `result/{DEVICE}/{PROJECT}/mcp_sink_decompile_request.json`

### Stage 6: Sink — IDA MCP Decompilation

Same as Stage 3 but for sink functions. Read `mcp_sink_decompile_request.json`.
Write results to `mcp_sink_decompile_result.json` with the same format as source result.

### Stage 7: Sink — LLM Classification

```bash
python3 liva.py {BINARY} {SEARCH_DIR} {DEVICE} --stages sink-llm
```

### Stage 8: Danger — Ghidra Analysis

```bash
python3 liva.py {BINARY} {SEARCH_DIR} {DEVICE} --stages danger-ghidra
```

Expected output: `result/{DEVICE}/{PROJECT}/mcp_danger_decompile_request.json`

The request file contains:
```json
{
  "type": "danger_decompile",
  "addresses": ["0x1234", "0x5678", ...]
}
```

### Stage 9: Danger — IDA MCP Decompilation (critical step)

The main binary is already open in an IDA session. Use its `session_id`.

For each address in `addresses`:
```
mcp__ida-mcp__decompile(session_id=MAIN_SID, addr="0xADDR")
```

Build the output JSON. Read `parent_child_calls.json` from:
`result/{DEVICE}/{PROJECT}/parent_child_calls.json`

For each item in `data[]`, look up `parent_address` in your decompile results map,
and add `"decompiled_c"` field. Items with no match get `"decompiled_c": null`.

Write the merged result to:
`result/{DEVICE}/{PROJECT}/parent_child_calls_ida_decompile.json`

Format:
```json
{
  "data": [
    {
      "parent_name": "usb_paswd_asp",
      "parent_address": "0x1234",
      "decompiled_c": "1: void usb_paswd_asp(...) {\n2: ...\n}",
      "children": [...],
      "child_names": ["system", "nvram_get"]
    }
  ]
}
```

Add line numbers to decompiled_c using:
```python
def add_line_numbers(code: str) -> str:
    return "\n".join(f"{i+1}: {line}" for i, line in enumerate(code.splitlines()))
```

### Stage 10: Taint Analysis (LLM)

```bash
python3 liva.py {BINARY} {SEARCH_DIR} {DEVICE} --stages taint
```

This reads `parent_child_calls_ida_decompile.json` and calls the fine-tuned Liva model.
Expected output: `result/{DEVICE}/{PROJECT}/taint_analysis.json`

### Stage 11: Neo4j Graph Import

```bash
python3 liva.py {BINARY} {SEARCH_DIR} {DEVICE} --stages neo4j
```

### Stage 12: Vulnerability Inference

```bash
python3 liva.py {BINARY} {SEARCH_DIR} {DEVICE} --stages infer
```

Expected output: `result/{DEVICE}/{PROJECT}/vul_result.txt`

## Final Report

Read and summarize `result/{DEVICE}/{PROJECT}/vul_result.txt`.
For each finding, report:
- Vulnerability type (command injection / buffer overflow)
- Source function (where user input enters)
- Sink function (dangerous function reached)
- Call chain
- Affected code snippet

## Error Recovery

| Error | Cause | Fix |
|-------|-------|-----|
| `FileNotFoundError: mcp_source_decompile_result.json` | Stage 3 not completed | Write the result file manually via MCP |
| `Session not found` in MCP | IDA not open | User must open binary in IDA Pro |
| `parent_child_calls.json not found` | Ghidra failed | Check `logs/GhidraAnalyzer.log` |
| `taint_analysis.json not found` | Taint stage not run | Run `--stages taint` first |
| Neo4j connection refused | Neo4j not running | Start Neo4j service |
```

- [ ] **Step 3: Verify skill file exists**

```bash
ls -la ~/.claude/skills/LIVA-MCP/skill.md
wc -l ~/.claude/skills/LIVA-MCP/skill.md
# Expected: file exists, ~160+ lines
```

- [ ] **Step 4: Commit**

```bash
git add docs/
git commit -m "feat: add LIVA-MCP skill file for IDA MCP-based pipeline orchestration"
```

---

## Task 6: Integration Smoke Test (dry-run)

This task verifies the full stage routing without needing real services.

**Files:** none changed — this is verification only

- [ ] **Step 1: Verify all new stages are accepted**

```bash
python3 liva.py /dev/null /tmp DevTest \
  --stages source-ghidra,source-llm,sink-ghidra,sink-llm,danger-ghidra \
  --dry-run
# Expected output:
# [Plan] Stages to run (in order): source-ghidra -> source-llm -> sink-ghidra -> sink-llm -> danger-ghidra
```

- [ ] **Step 2: Verify unknown stage rejection still works**

```bash
python3 liva.py /dev/null /tmp DevTest --stages fake-stage 2>&1
# Expected: "error: Unknown stage(s): fake-stage"
```

- [ ] **Step 3: Verify bridge unit tests still pass**

```bash
pytest tests/test_ida_mcp_bridge.py -v
# Expected: 5 tests PASSED
```

- [ ] **Step 4: Verify original stages unaffected**

```bash
python3 liva.py /dev/null /tmp DevTest --stages elf,source,sink,danger,taint,neo4j,infer --dry-run
# Expected: original 7 stages listed correctly
```

- [ ] **Step 5: Final commit**

```bash
git add .
git commit -m "chore: verify all stages and smoke tests pass for LIVA-MCP integration"
```

---

## Self-Review

**Spec coverage:**
- ✅ Replace Windows IDA HTTP service with IDA MCP → Tasks 1–4 + skill Stage 3/6/9
- ✅ Keep all original LIVA functionality → original stages unchanged, new sub-stages additive
- ✅ Package as Claude Code skill → Task 5
- ✅ All 7 original stages preserved → `--stages elf,source,...` still works
- ✅ source/sink/danger split for MCP injection → Tasks 2/3/4
- ✅ Bridge request/result file protocol → Task 1

**Placeholder scan:** No TBD/TODO in task code. All function signatures and return shapes are explicit.

**Type consistency:**
- `IDAMCPBridge.SOURCE_RESULT` used in Task 1, Task 2, Task 5 — consistent
- `batch_resp` format in `run_stage_sink_llm` matches the result format written in skill Stage 6
- `parent_child_calls_ida_decompile.json` format in skill Stage 9 matches what `DangerFuncAnalyzer.run_dangercompile_IDA()` and `TaintAnalyzer.gpt_preprocess()` expect at [core/taint_analyzer.py:282](../../core/taint_analyzer.py#L282)
