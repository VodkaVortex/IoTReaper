# LIVA macOS + Relay API + IDA-MCP Transformation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform LIVA-main to run on macOS by replacing the Windows IDA HTTP service with local IDA-MCP, all LLM calls with an OpenAI-compatible relay API, and removing the Neo4j dependency entirely.

**Architecture:** IDA decompilation calls are redirected to the local `ida-mcp-main` Python library (session-based named-pipe IPC with IDA Pro); all LLM calls switch from raw `requests.post` to the `openai` library with a configurable `relay_base_url`; the Neo4j graph is replaced with an in-memory DFS path finder over the Ghidra-generated call graph already stored in `parent_child_calls_ida_decompile.json`.

**Tech Stack:** Python 3.10+, `openai` library (already used for taint stage), `ida-mcp-main` at `/Users/yangshuangning/VscodeProjects/ida-mcp-main`, conda env `iotreaper`, Ghidra headless, macOS

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `config/config.ini` | Switch endpoints: relay API, IDA-MCP path, remove Neo4j |
| Modify | `core/llm/llm_request.py` | Use `openai.OpenAI` instead of raw `requests.post` |
| Create | `core/idanet/IDAMCPClient.py` | Drop-in replacement for `WindowsIDAClient` via `ida-mcp-main` |
| Modify | `liva.py` (source/sink stages) | Swap `WindowsIDAClient` → `IDAMCPClient` |
| Modify | `core/danger_func_analyzer.py` | Replace `_stream_post_decompile` with `IDAMCPClient` |
| Create | `core/simple_path_finder.py` | In-memory source→sink path finding (replaces Neo4j) |
| Modify | `liva.py` (neo4j/infer stages) | Remove neo4j stage, wire `SimplePathFinder` into infer |
| Delete | `core/neo4j_opt.py` | No longer needed |
| Delete | `core/gen_neo4j_input.py` | No longer needed |
| Delete | `core/taint_path_finder.py` | No longer needed |
| Delete | `core/idanet/WindowsIDAClient.py` | Replaced by `IDAMCPClient` |
| Create | `tests/test_idamcp_client.py` | Unit tests for IDAMCPClient |
| Create | `tests/test_simple_path_finder.py` | Unit tests for SimplePathFinder |
| Create | `tests/test_llm_request.py` | Unit tests for Chatbot relay API |

---

## Task 1: Update config.ini

**Files:**
- Modify: `config/config.ini`

- [ ] **Step 1: Replace `[LLM]` endpoint with relay API format**

Open `config/config.ini` and replace the `[LLM]` section so it points at a configurable relay base URL (the `/v1/chat/completions` suffix is added by the openai library automatically):

```ini
[LLM]
api_key = YOUR_RELAY_API_KEY
base_url = https://api.gpt.ge/v1
proxy =
model = deepseek-v3
max_tokens = 4000
temperature = 0.6
top_p = 1
n = 1
```

- [ ] **Step 2: Replace `[Fine-tuning]` endpoint with relay API**

The taint stage (liva.py `run_stage_taint`) already uses `openai.OpenAI`. Just change its config to point at the relay instead of the private Liva server:

```ini
[Fine-tuning]
api_key = YOUR_RELAY_API_KEY
base_url = https://api.gpt.ge/v1
model = deepseek-v3
max_tokens = 8196
temperature = 0.6
timeout = 30
retries = 2
```

- [ ] **Step 3: Replace `[Reverse]` section with `[IDAMCP]`**

Remove the Windows IDA service URL and replace with IDA-MCP path:

```ini
[IDAMCP]
ida_mcp_path = /Users/yangshuangning/VscodeProjects/ida-mcp-main
ida_dir = /Applications/IDA Professional 9.3.app
```

- [ ] **Step 4: Remove `[Neo4j]` section entirely**

Delete these lines from `config/config.ini`:
```ini
[Neo4j]
uri = neo4j://192.168.0.121:7687
user = neo4j
password = 1qaz@WSX
database = neo4j
```

- [ ] **Step 5: Verify config.ini has no broken references**

Run:
```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main && python3 -c "
import configparser
c = configparser.ConfigParser()
c.read('config/config.ini')
print('Sections:', c.sections())
assert 'Neo4j' not in c.sections(), 'Neo4j still present'
assert 'IDAMCP' in c.sections(), 'IDAMCP missing'
assert 'base_url' in c['LLM'], 'LLM base_url missing'
print('OK')
"
```
Expected output: `Sections: [...]` followed by `OK`

- [ ] **Step 6: Commit**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
git add config/config.ini
git commit -m "config: switch to relay API, IDA-MCP, remove Neo4j config"
```

---

## Task 2: Refactor core/llm/llm_request.py to use openai relay

**Files:**
- Modify: `core/llm/llm_request.py`
- Create: `tests/test_llm_request.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_llm_request.py`:

```python
from unittest.mock import MagicMock, patch
import pytest

def test_chatbot_calls_openai_with_relay(tmp_path):
    """Chatbot.chat() should call openai.OpenAI with base_url from config."""
    ini = tmp_path / "config.ini"
    ini.write_text("""
[LLM]
api_key = test-key
base_url = https://relay.example.com/v1
proxy =
model = gpt-4o-mini
max_tokens = 100
temperature = 0.5
top_p = 1
n = 1

[Fine-tuning]
api_key = test-key
base_url = https://relay.example.com/v1
model = gpt-4o-mini
max_tokens = 100
temperature = 0.5
timeout = 10
retries = 1

[Session]
source_session = /nonexistent_source.json
sink_session = /nonexistent_sink.json
vul_session = /nonexistent_vul.json
""")
    mock_response = MagicMock()
    mock_response.choices = [MagicMock()]
    mock_response.choices[0].message.content = "***nvram_get***"

    with patch("core.llm.llm_request.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        MockOpenAI.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        from core.llm.llm_request import Chatbot
        bot = Chatbot(config_file=str(ini), chat_type="other")
        result = bot.chat("test input")

    MockOpenAI.assert_called_once_with(
        api_key="test-key",
        base_url="https://relay.example.com/v1",
    )
    assert b"nvram_get" in result


def test_chatbot_returns_error_bytes_on_api_failure(tmp_path):
    """Chatbot.chat() returns b'error' when openai raises an exception."""
    ini = tmp_path / "config.ini"
    ini.write_text("""
[LLM]
api_key = test-key
base_url = https://relay.example.com/v1
proxy =
model = gpt-4o-mini
max_tokens = 100
temperature = 0.5
top_p = 1
n = 1

[Session]
source_session = /nonexistent.json
sink_session = /nonexistent.json
vul_session = /nonexistent.json
""")
    with patch("core.llm.llm_request.OpenAI") as MockOpenAI:
        mock_client = MagicMock()
        MockOpenAI.return_value = mock_client
        mock_client.chat.completions.create.side_effect = Exception("connection refused")

        from core.llm.llm_request import Chatbot
        bot = Chatbot(config_file=str(ini), chat_type="other")
        result = bot.chat("test input")

    assert result == b"error"
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -m pytest tests/test_llm_request.py -v 2>&1 | head -30
```
Expected: `ImportError` or `ModuleNotFoundError` for `core.llm.llm_request.OpenAI` since the current code uses `requests`.

- [ ] **Step 3: Rewrite core/llm/llm_request.py**

Replace the entire file with:

```python
import configparser
import json
import logging
import os
from openai import OpenAI


class Chatbot:
    def __init__(self, config_file='config.ini', chat_type="source", gpt_model=None, api_key_prefix='LLM'):
        self.config = self._load_config(config_file)
        section = self.config[api_key_prefix]
        self.api_key = section['api_key']
        self.base_url = section.get('base_url', section.get('endpoint', ''))
        self.model = gpt_model or section['model']
        self.max_tokens = int(section['max_tokens'])
        self.temperature = float(section['temperature'])
        self.top_p = int(section.get('top_p', 1))
        self.n = int(section.get('n', 1))

        if chat_type == "source":
            self.session_file_path = self.config['Session']['source_session']
        elif chat_type == "sink":
            self.session_file_path = self.config['Session']['sink_session']
        elif chat_type == "vul":
            self.session_file_path = self.config['Session']['vul_session']
        else:
            self.session_file_path = ""

        self.messages = self._load_messages()
        self._client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def _load_config(self, config_file):
        cfg = configparser.ConfigParser()
        cfg.read(config_file)
        return cfg

    def _load_messages(self):
        if self.session_file_path and os.path.exists(self.session_file_path):
            with open(self.session_file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return [{"role": "system", "content": "You are a binary security analysis expert."}]

    def chat(self, user_input: str) -> bytes:
        messages = self.messages.copy()
        messages.append({"role": "user", "content": user_input})
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                top_p=self.top_p,
                n=self.n,
            )
        except Exception as exc:
            logging.error(f"LLM request error: {exc}")
            return b"error"

        try:
            text = resp.choices[0].message.content.strip()
            if '\r\n' not in text:
                text = text.replace('\n', '\r\n')
            return (text + '\r\n\r\n').encode("utf-8")
        except Exception as exc:
            logging.error(f"LLM response parse error: {exc}")
            return b"error"
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -m pytest tests/test_llm_request.py -v
```
Expected: `2 passed`

- [ ] **Step 5: Commit**

```bash
git add core/llm/llm_request.py tests/test_llm_request.py
git commit -m "feat: switch Chatbot to openai relay API"
```

---

## Task 3: Create core/idanet/IDAMCPClient.py

**Files:**
- Create: `core/idanet/IDAMCPClient.py`
- Create: `tests/test_idamcp_client.py`

IDA-MCP return formats (from `ida_functions/query.py` handlers):
- `decompile`: `{"ok": True, "function_name": "...", "start_ea": "0x...", "decompilation": "<C pseudocode>"}`
- `lookup_funcs`: `{"ok": True, "functions": [{"name": "...", "start_ea": "0x...", "end_ea": "0x...", "size": N, "matched_by": "...", "query": "..."}], "unresolved": [...]}`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_idamcp_client.py`:

```python
import sys
from unittest.mock import MagicMock, patch
import pytest


@pytest.fixture(autouse=True)
def mock_ida_mcp_imports():
    """Mock out the ida-mcp-main modules so tests run without IDA installed."""
    mock_tools_session = MagicMock()
    mock_ida_query = MagicMock()
    sys.modules['tools_session'] = mock_tools_session
    sys.modules['ida_tools'] = MagicMock()
    sys.modules['ida_tools.query'] = mock_ida_query
    yield mock_tools_session, mock_ida_query
    del sys.modules['tools_session']
    del sys.modules['ida_tools']
    del sys.modules['ida_tools.query']


def _make_client(mock_ts, mock_q, ida_mcp_path="/fake/ida-mcp"):
    from core.idanet.IDAMCPClient import IDAMCPClient
    return IDAMCPClient(ida_mcp_path=ida_mcp_path)


def test_send_multiple_libs_returns_windowed_format(mock_ida_mcp_imports):
    mock_ts, mock_q = mock_ida_mcp_imports
    # analyze_binary returns session_id
    mock_ts.analyze_binary.return_value = {"ok": True, "session_id": 42}
    # probe_ready returns immediately ready
    mock_ts.probe_ready.return_value = {"ok": True, "ready": True}
    # lookup_funcs finds the function
    mock_q.lookup_funcs.return_value = {
        "ok": True, "functions": [{"start_ea": "0x1234", "name": "nvram_get"}], "unresolved": []
    }
    # decompile returns pseudocode
    mock_q.decompile.return_value = {
        "ok": True, "decompilation": "char *nvram_get(char *key) { return lookup(key); }"
    }

    client = _make_client(mock_ts, mock_q)
    result = client.send_multiple_libs(
        file_mapping={"libnvram.so": "/fake/libnvram.so"},
        funcs_by_lib={"libnvram.so": ["nvram_get"]},
    )

    assert "libnvram.so" in result
    assert result["libnvram.so"]["status"] == 200
    assert "nvram_get" in result["libnvram.so"]["resp"]
    assert "nvram_get" in result["libnvram.so"]["resp"]["nvram_get"]["code"]


def test_decompile_addresses_returns_addr_to_code_map(mock_ida_mcp_imports):
    mock_ts, mock_q = mock_ida_mcp_imports
    mock_ts.analyze_binary.return_value = {"ok": True, "session_id": 99}
    mock_ts.probe_ready.return_value = {"ok": True, "ready": True}
    mock_q.decompile.return_value = {
        "ok": True, "decompilation": "void system_wrapper() { system(cmd); }"
    }

    client = _make_client(mock_ts, mock_q)
    result = client.decompile_addresses("/fake/jhttpd", ["0x1000", "0x2000"])

    assert "0x1000" in result
    assert "system_wrapper" in result["0x1000"]


def test_lookup_not_found_gives_empty_code(mock_ida_mcp_imports):
    mock_ts, mock_q = mock_ida_mcp_imports
    mock_ts.analyze_binary.return_value = {"ok": True, "session_id": 7}
    mock_ts.probe_ready.return_value = {"ok": True, "ready": True}
    mock_q.lookup_funcs.return_value = {
        "ok": True, "functions": [], "unresolved": ["unknown_func"]
    }

    client = _make_client(mock_ts, mock_q)
    result = client.send_multiple_libs(
        file_mapping={"lib.so": "/fake/lib.so"},
        funcs_by_lib={"lib.so": ["unknown_func"]},
    )

    assert result["lib.so"]["resp"]["unknown_func"]["code"] == ""
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -m pytest tests/test_idamcp_client.py -v 2>&1 | head -20
```
Expected: `ImportError: cannot import name 'IDAMCPClient'`

- [ ] **Step 3: Create core/idanet/IDAMCPClient.py**

```python
import sys
import time
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class IDAMCPClient:
    """
    Drop-in replacement for WindowsIDAClient.
    Uses the local ida-mcp-main project to decompile via IDA Pro on macOS.

    IDA-MCP return formats:
      decompile  → {"ok": True, "decompilation": "<C pseudocode>", "function_name": "..."}
      lookup_funcs → {"ok": True, "functions": [{"start_ea": "0x..."}], "unresolved": [...]}
    """

    def __init__(
        self,
        ida_mcp_path: str = "/Users/yangshuangning/VscodeProjects/ida-mcp-main",
        ida_dir: str = "",
        probe_timeout_sec: int = 300,
        probe_interval_sec: int = 5,
    ):
        self.ida_mcp_path = str(ida_mcp_path)
        self.ida_dir = ida_dir
        self.probe_timeout_sec = probe_timeout_sec
        self.probe_interval_sec = probe_interval_sec
        self._session_cache: Dict[str, int] = {}

        # Add ida-mcp-main to path once
        if self.ida_mcp_path not in sys.path:
            sys.path.insert(0, self.ida_mcp_path)

        import tools_session as _ts
        import ida_tools.query as _q
        self._ts = _ts
        self._q = _q

    def _get_or_create_session(self, binary_path: str) -> int:
        if binary_path in self._session_cache:
            return self._session_cache[binary_path]

        result = self._ts.analyze_binary(
            binary_path=binary_path,
            ida_dir=self.ida_dir,
        )
        if not result.get("ok"):
            raise RuntimeError(
                f"IDA-MCP analyze_binary failed for {binary_path}: {result.get('error', result)}"
            )
        session_id: int = result["session_id"]
        logger.info("IDA session %d created for %s, waiting for ready...", session_id, binary_path)

        deadline = time.time() + self.probe_timeout_sec
        while time.time() < deadline:
            status = self._ts.probe_ready(session_id, timeout_sec=self.probe_interval_sec)
            if status.get("ready"):
                logger.info("IDA session %d ready", session_id)
                self._session_cache[binary_path] = session_id
                return session_id
            logger.debug("session %d not ready yet: %s", session_id, status.get("message", ""))
            time.sleep(self.probe_interval_sec)

        raise TimeoutError(
            f"IDA session {session_id} did not become ready within {self.probe_timeout_sec}s"
        )

    def _decompile_one(self, session_id: int, func_name: str) -> str:
        lookup = self._q.lookup_funcs(session_id, queries=[func_name])
        if not lookup.get("ok"):
            logger.warning("lookup_funcs failed for %s: %s", func_name, lookup.get("error"))
            return ""
        funcs = lookup.get("functions", [])
        if not funcs:
            logger.debug("Function not found in IDA: %s", func_name)
            return ""
        addr = funcs[0].get("start_ea", "")
        if not addr:
            return ""
        decomp = self._q.decompile(session_id, addr=addr)
        if not decomp.get("ok"):
            logger.warning("decompile failed at %s: %s", addr, decomp.get("error"))
            return ""
        return decomp.get("decompilation", "")

    def send_multiple_libs(
        self,
        file_mapping: Dict[str, str],
        funcs_by_lib: Dict[str, List[str]],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Drop-in replacement for WindowsIDAClient.send_multiple_libs.

        Returns:
            {
              "libnvram.so": {
                "status": 200,
                "resp": {
                  "nvram_get": {"code": "<C pseudocode>", "inlined_from": []}
                }
              }
            }
        """
        results: Dict[str, Any] = {}
        for libname, func_list in funcs_by_lib.items():
            binary_path = file_mapping.get(libname, "")
            if not binary_path or not Path(binary_path).exists():
                results[libname] = {"binary": libname, "error": f"binary not found: {binary_path}"}
                continue
            try:
                session_id = self._get_or_create_session(binary_path)
                resp: Dict[str, Any] = {}
                for func_name in func_list:
                    code = self._decompile_one(session_id, func_name)
                    resp[func_name] = {"code": code, "inlined_from": []}
                results[libname] = {"status": 200, "resp": resp}
            except Exception as exc:
                logger.error("IDA-MCP error for %s: %s", libname, exc)
                results[libname] = {"binary": libname, "error": str(exc)}
        return results

    def decompile_addresses(
        self,
        binary_path: str,
        addresses: List[str],
    ) -> Dict[str, str]:
        """
        Decompile functions by address (used in danger stage).

        Returns:
            {"0x1000": "<C pseudocode>", "0x2000": "<C pseudocode>", ...}
        """
        results: Dict[str, str] = {}
        session_id = self._get_or_create_session(binary_path)
        for addr in addresses:
            decomp = self._q.decompile(session_id, addr=addr)
            if decomp.get("ok"):
                results[addr] = decomp.get("decompilation", "")
            else:
                logger.warning("decompile at %s failed: %s", addr, decomp.get("error"))
                results[addr] = ""
        return results

    def cleanup(self) -> None:
        import tools_session as ts
        for binary_path, session_id in list(self._session_cache.items()):
            try:
                ts.end_session(session_id)
                logger.info("Ended IDA session %d for %s", session_id, binary_path)
            except Exception as exc:
                logger.warning("Failed to end session %d: %s", session_id, exc)
        self._session_cache.clear()
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -m pytest tests/test_idamcp_client.py -v
```
Expected: `3 passed`

- [ ] **Step 5: Commit**

```bash
git add core/idanet/IDAMCPClient.py tests/test_idamcp_client.py
git commit -m "feat: add IDAMCPClient replacing WindowsIDAClient"
```

---

## Task 4: Replace WindowsIDAClient in liva.py source and sink stages

**Files:**
- Modify: `liva.py` lines 6, 74–89, 134–145

- [ ] **Step 1: Update imports in liva.py**

In `liva.py`, replace line 6:
```python
from core.idanet.WindowsIDAClient import WindowsIDAClient
```
with:
```python
from core.idanet.IDAMCPClient import IDAMCPClient
```

- [ ] **Step 2: Update run_stage_source() IDA client instantiation (lines 74–89)**

Replace:
```python
        client = WindowsIDAClient(
            base_url="http://192.168.0.3:8082",
            token="SuperSecret123",
            device=config.LivaConfig.project_path  # 这个会作为目录名出现在 Windows 端
            )
        funcs_by_lib = grouped
        file_mapping = {}
        for binary in grouped:
            file_mapping[binary] = f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}/iot_file/{binary}"
        batch_resp = client.send_multiple_libs(
            file_mapping=file_mapping,
            funcs_by_lib=funcs_by_lib,
            feature="source_decompile",
            create_func=True,
            timeout_sec=180,
        )
```
with:
```python
        idamcp_config = config.LivaConfig.config["IDAMCP"]
        client = IDAMCPClient(
            ida_mcp_path=idamcp_config["ida_mcp_path"],
            ida_dir=idamcp_config.get("ida_dir", ""),
        )
        funcs_by_lib = grouped
        file_mapping = {}
        for binary in grouped:
            file_mapping[binary] = f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}/iot_file/{binary}"
        batch_resp = client.send_multiple_libs(
            file_mapping=file_mapping,
            funcs_by_lib=funcs_by_lib,
        )
```

- [ ] **Step 3: Update run_stage_sink() IDA client instantiation (lines 134–145)**

Replace:
```python
        client = WindowsIDAClient(
        base_url="http://192.168.0.3:8082",
        token="SuperSecret123",
        device=config.LivaConfig.project_path  # 这个会作为目录名出现在 Windows 端
        )
        batch_resp = client.send_multiple_libs(
            file_mapping=file_mapping,
            funcs_by_lib=funcs_by_lib,
            feature="source_decompile",
            create_func=True,
            timeout_sec=180,
        )
```
with:
```python
        idamcp_config = config.LivaConfig.config["IDAMCP"]
        client = IDAMCPClient(
            ida_mcp_path=idamcp_config["ida_mcp_path"],
            ida_dir=idamcp_config.get("ida_dir", ""),
        )
        batch_resp = client.send_multiple_libs(
            file_mapping=file_mapping,
            funcs_by_lib=funcs_by_lib,
        )
```

- [ ] **Step 4: Verify liva.py syntax**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -c "import liva" 2>&1 | head -20
```
Expected: No import errors (may fail on missing config file, that's acceptable)

- [ ] **Step 5: Commit**

```bash
git add liva.py
git commit -m "feat: replace WindowsIDAClient with IDAMCPClient in source/sink stages"
```

---

## Task 5: Update core/danger_func_analyzer.py

**Files:**
- Modify: `core/danger_func_analyzer.py`

The `DangerFuncAnalyzer.run_dangercompile_IDA()` currently streams binary data to an HTTP endpoint. We replace this with `IDAMCPClient.decompile_addresses()`.

- [ ] **Step 1: Replace `__init__` parameters and add IDAMCPClient**

In `danger_func_analyzer.py`, replace the `DangerFuncAnalyzer.__init__` (line 101–108) and remove `_stream_post_decompile` (lines 26–62):

Remove the entire `_stream_post_decompile` function (lines 25–62).

Replace `DangerFuncAnalyzer.__init__` from:
```python
class DangerFuncAnalyzer:
    def __init__(self, service_url: str, token: str, verify_ssl: bool = False):
        self.service_url = service_url
        self.token = token
        self.verify_ssl = verify_ssl
        self.bin_path = Path(config.LivaConfig.binary_path)
        self.logger = LoggerConfig.configure_logger('DangerFuncAnalyzer')
        self.runner = UnifiedGhidraRunner()
```
to:
```python
class DangerFuncAnalyzer:
    def __init__(self, ida_mcp_path: str = "", ida_dir: str = ""):
        from core.idanet.IDAMCPClient import IDAMCPClient
        self._client = IDAMCPClient(
            ida_mcp_path=ida_mcp_path or "/Users/yangshuangning/VscodeProjects/ida-mcp-main",
            ida_dir=ida_dir,
        )
        self.bin_path = Path(config.LivaConfig.binary_path)
        self.logger = LoggerConfig.configure_logger('DangerFuncAnalyzer')
        self.runner = UnifiedGhidraRunner()
```

- [ ] **Step 2: Replace `run_dangercompile_IDA` body to use IDAMCPClient**

Replace the IDA-calling section in `run_dangercompile_IDA` (lines 173–186):

Remove:
```python
        # 调用 IDA
        _stream_post_decompile(
            url=self.service_url,
            token=self.token,
            addrs_csv=addrs_csv,
            bin_path=self.bin_path,
            out_json_path=out_json_path,
            create_func=create_func,
            verify_ssl=self.verify_ssl,
        )

        code_map = _load_ida_out_as_map(out_json_path)
```

Replace with:
```python
        code_map = self._client.decompile_addresses(
            binary_path=str(self.bin_path),
            addresses=addrs_norm,
        )
```

Also remove the `out_json_path` variable since it's no longer needed. Remove this line too (line 122):
```python
        out_json_path = base_dir / "out.json"
```

- [ ] **Step 3: Update liva.py run_stage_danger() to not pass service_url**

In `liva.py`, replace the `DangerFuncAnalyzer` instantiation (lines 276–277):

From:
```python
        reverse_config = config.LivaConfig.config["Reverse"]
        danger_func = DangerFuncAnalyzer(service_url=reverse_config["ida_url"], token=reverse_config["token"],)
```

To:
```python
        idamcp_config = config.LivaConfig.config["IDAMCP"]
        danger_func = DangerFuncAnalyzer(
            ida_mcp_path=idamcp_config["ida_mcp_path"],
            ida_dir=idamcp_config.get("ida_dir", ""),
        )
```

- [ ] **Step 4: Remove unused imports from danger_func_analyzer.py**

Remove `import requests` and `CHUNK_SIZE = 1024 * 1024` from the top since `_stream_post_decompile` is gone.

- [ ] **Step 5: Verify syntax**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -c "from core.danger_func_analyzer import DangerFuncAnalyzer; print('OK')"
```
Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add core/danger_func_analyzer.py liva.py
git commit -m "feat: replace Windows IDA HTTP service with IDAMCPClient in danger stage"
```

---

## Task 6: Create core/simple_path_finder.py

**Files:**
- Create: `core/simple_path_finder.py`
- Create: `tests/test_simple_path_finder.py`

**Design:** Read `parent_child_calls_ida_decompile.json`. For each parent function that has both a source function call AND a dangerous sink call in its `child_names`, emit a path dict compatible with what `VulInfer.build_reports()` expects.

The path dict format (matching Neo4j output in `run_stage_neo4j`):
```python
{
    "src": {"param_func": "websGetVar", "func_name": "parent_func_name"},
    "dst": {"func_name": "system"},
    "rels": []
}
```

- [ ] **Step 1: Write failing tests**

Create `tests/test_simple_path_finder.py`:

```python
import json
import pytest
from pathlib import Path


SAMPLE_PARENT_CHILD = {
    "data": [
        {
            "parent_name": "handle_request",
            "parent_address": "0x1000",
            "child_names": ["websGetVar", "system", "printf"],
            "decompiled_c": "1: void handle_request() {\n2:   v = websGetVar(...);\n3:   system(v);\n4: }"
        },
        {
            "parent_name": "safe_func",
            "parent_address": "0x2000",
            "child_names": ["printf", "strlen"],
            "decompiled_c": "1: void safe_func() {}"
        },
        {
            "parent_name": "multi_sink",
            "parent_address": "0x3000",
            "child_names": ["httpd_get_parm", "popen", "system"],
            "decompiled_c": "1: void multi_sink() {}"
        }
    ]
}


@pytest.fixture
def parent_child_file(tmp_path):
    p = tmp_path / "parent_child_calls_ida_decompile.json"
    p.write_text(json.dumps(SAMPLE_PARENT_CHILD), encoding="utf-8")
    return p


def test_finds_direct_source_to_sink_path(parent_child_file):
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=parent_child_file,
        source_funcs=["websGetVar"],
        sink_funcs=["system", "popen"],
    )
    assert len(paths) >= 1
    src_funcs = {p["src"]["func_name"] for p in paths}
    assert "handle_request" in src_funcs


def test_skips_functions_without_source(parent_child_file):
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=parent_child_file,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
    )
    dst_funcs = {p["src"]["func_name"] for p in paths}
    assert "safe_func" not in dst_funcs


def test_multiple_sinks_from_same_parent(parent_child_file):
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=parent_child_file,
        source_funcs=["httpd_get_parm"],
        sink_funcs=["popen", "system"],
    )
    sink_names = {p["dst"]["func_name"] for p in paths}
    assert "popen" in sink_names
    assert "system" in sink_names


def test_path_has_expected_structure(parent_child_file):
    from core.simple_path_finder import find_source_sink_paths
    paths = find_source_sink_paths(
        parent_child_path=parent_child_file,
        source_funcs=["websGetVar"],
        sink_funcs=["system"],
    )
    p = paths[0]
    assert "src" in p and "dst" in p and "rels" in p
    assert "param_func" in p["src"]
    assert "func_name" in p["src"]
    assert "func_name" in p["dst"]
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -m pytest tests/test_simple_path_finder.py -v 2>&1 | head -20
```
Expected: `ModuleNotFoundError: No module named 'core.simple_path_finder'`

- [ ] **Step 3: Create core/simple_path_finder.py**

```python
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


def find_source_sink_paths(
    parent_child_path: str | Path,
    source_funcs: List[str],
    sink_funcs: List[str],
) -> List[Dict[str, Any]]:
    """
    Find source-to-sink paths without Neo4j.

    Reads parent_child_calls_ida_decompile.json and emits path dicts
    compatible with VulInfer.build_reports().

    A path is emitted when a parent function directly calls BOTH
    a source function (e.g. websGetVar) AND a sink function (e.g. system).

    Returns:
        [
          {
            "src": {"param_func": "websGetVar", "func_name": "handle_request"},
            "dst": {"func_name": "system"},
            "rels": []
          },
          ...
        ]
    """
    path = Path(parent_child_path)
    if not path.exists():
        logger.warning("parent_child_calls_ida_decompile.json not found: %s", path)
        return []

    root = json.loads(path.read_text(encoding="utf-8"))
    items: List[Dict[str, Any]] = root.get("data", [])

    source_set = set(source_funcs)
    sink_set = set(sink_funcs)
    paths: List[Dict[str, Any]] = []

    for item in items:
        parent_name: str = item.get("parent_name", "")
        child_names: List[str] = item.get("child_names", [])
        child_set = set(child_names)

        found_sources = child_set & source_set
        found_sinks = child_set & sink_set

        if not found_sources or not found_sinks:
            continue

        for src_func in sorted(found_sources):
            for sink_func in sorted(found_sinks):
                paths.append({
                    "src": {
                        "param_func": src_func,
                        "func_name": parent_name,
                    },
                    "dst": {
                        "func_name": sink_func,
                    },
                    "rels": [],
                })

    logger.info("SimplePathFinder: found %d source→sink paths", len(paths))
    return paths
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -m pytest tests/test_simple_path_finder.py -v
```
Expected: `4 passed`

- [ ] **Step 5: Commit**

```bash
git add core/simple_path_finder.py tests/test_simple_path_finder.py
git commit -m "feat: add SimplePathFinder replacing Neo4j taint path queries"
```

---

## Task 7: Remove Neo4j stage from liva.py and wire SimplePathFinder into infer

**Files:**
- Modify: `liva.py` (neo4j stage removal + infer stage rewrite)

- [ ] **Step 1: Remove `from core.neo4j_opt import ParamGraphIngestor` from liva.py**

In `liva.py` line 11, remove:
```python
from core.neo4j_opt import ParamGraphIngestor
```

- [ ] **Step 2: Add SimplePathFinder import**

Add after the `from core.vulinfer import VulInfer` import:
```python
from core.simple_path_finder import find_source_sink_paths
```

- [ ] **Step 3: Delete run_stage_neo4j() entirely (lines 366–399)**

Remove the entire `run_stage_neo4j()` function:
```python
def run_stage_neo4j():
    neo4j_config = config.LivaConfig.config["Neo4j"]
    with ParamGraphIngestor(
        ...
    ) as ingestor:
        ...
        config.neo4j_paths = paths
        ...
```

- [ ] **Step 4: Rewrite run_stage_infer() to use SimplePathFinder**

Replace the existing `run_stage_infer()` (lines 401–414) with:

```python
def run_stage_infer():
    from pathlib import Path as _Path
    base_dir = _Path(f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}")
    parent_child_file = base_dir / "parent_child_calls_ida_decompile.json"

    vul_funcs = config.LivaConfig.config["VulFunction"]
    sink_funcs = (
        [s.strip() for s in vul_funcs["command_injection"].split(",") if s.strip()]
        + [s.strip() for s in vul_funcs["buffer_overflow"].split(",") if s.strip()]
    )
    source_funcs = config.LivaConfig.source_point or ["websGetVar", "cgiFormString", "httpd_get_parm"]

    paths = find_source_sink_paths(
        parent_child_path=parent_child_file,
        source_funcs=source_funcs,
        sink_funcs=sink_funcs,
    )
    print(f"Found {len(paths)} source→sink paths")

    vulinfer = VulInfer(
        ida_json_path=parent_child_file,
        output_path=base_dir / "cmd_injection_candidates.txt",
    )
    first_source = source_funcs[0] if source_funcs else "websGetVar"
    reports = vulinfer.build_reports(paths=paths, source_func_name=first_source)
    merge_report = vulinfer.merge_by_call_chain(reports)
    print(f"Generated {len(merge_report)} merged reports")
    vulinfer.gpt_infer(merge_report, str(base_dir / "vul_result.txt"))
```

- [ ] **Step 5: Remove "neo4j" from RUN_ORDER and stage dispatcher**

In `liva.py` line 419, change:
```python
    RUN_ORDER = ["elf", "source", "sink", "danger", "taint","neo4j","infer"]
```
to:
```python
    RUN_ORDER = ["elf", "source", "sink", "danger", "taint", "infer"]
```

Remove the `elif stage == "neo4j":` block (lines 487–488):
```python
            elif stage == "neo4j":
                run_with_timer("neo4j", run_stage_neo4j)
```

- [ ] **Step 6: Remove config.neo4j_paths reference from config/config.py**

In `config/config.py` line 19, remove:
```python
neo4j_paths = None
```

- [ ] **Step 7: Verify liva.py dry-run works**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 liva.py /tmp/test.bin /tmp/ TestDevice --dry-run
```
Expected output includes:
```
[Plan] Stages to run (in order): elf -> source -> sink -> danger -> taint -> infer
```
And NOT `neo4j`.

- [ ] **Step 8: Commit**

```bash
git add liva.py config/config.py
git commit -m "feat: remove neo4j stage, wire SimplePathFinder into infer"
```

---

## Task 8: Delete unused files

**Files:**
- Delete: `core/neo4j_opt.py`
- Delete: `core/gen_neo4j_input.py`
- Delete: `core/taint_path_finder.py`
- Delete: `core/idanet/WindowsIDAClient.py`

- [ ] **Step 1: Verify nothing imports the files being deleted**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
grep -r "neo4j_opt\|gen_neo4j_input\|taint_path_finder\|WindowsIDAClient" \
  --include="*.py" . | grep -v "^./core/neo4j_opt\|^./core/gen_neo4j_input\|^./core/taint_path_finder\|^./core/idanet/WindowsIDAClient"
```
Expected: No output (no remaining imports).

- [ ] **Step 2: Delete the files**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
rm core/neo4j_opt.py core/gen_neo4j_input.py core/taint_path_finder.py core/idanet/WindowsIDAClient.py
```

- [ ] **Step 3: Verify tests still pass**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -m pytest tests/ -v
```
Expected: All previously passing tests still pass; no `ImportError` for deleted modules.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: remove WindowsIDAClient, neo4j_opt, gen_neo4j_input, taint_path_finder"
```

---

## Task 9: macOS compatibility fixes

**Files:**
- Modify: `config/config.py` (ensure HEADLESS_GHIDRA path is correct for macOS)
- Modify: `core/ghidra_analyzer.py` (verify no Windows-only shell assumptions)

- [ ] **Step 1: Verify Ghidra headless path exists on macOS**

```bash
ls /Users/yangshuangning/VscodeProjects/LIVA-main/ghidra/support/analyzeHeadless 2>/dev/null \
  && echo "Ghidra found" || echo "Ghidra NOT found at expected path"
```

If not found, note the actual Ghidra path and update `config/config.py` line 13:
```python
HEADLESS_GHIDRA = os.path.join(HOME, "ghidra", "support", "analyzeHeadless")
```
to the correct path.

- [ ] **Step 2: Verify conda environment exists**

```bash
conda run -n iotreaper python3 --version
```
Expected: Python 3.10+ output. If missing, create it:
```bash
conda create -n iotreaper python=3.10 -y
conda run -n iotreaper pip install openai sqlalchemy readelf requests pathlib
```

- [ ] **Step 3: Install openai if missing**

```bash
conda run -n iotreaper pip show openai 2>/dev/null | grep Version || \
  conda run -n iotreaper pip install openai
```

- [ ] **Step 4: Verify no hardcoded Windows paths remain**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
grep -rn "192\.168\.\|\\\\Users\|C:\\\\|8081\|8082\|SuperSecret123" \
  --include="*.py" . | grep -v ".pyc" | grep -v "test_"
```
Expected: No output (all Windows IPs and tokens removed).

- [ ] **Step 5: Run the full import check**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -c "
from core.llm.llm_request import Chatbot
from core.idanet.IDAMCPClient import IDAMCPClient
from core.simple_path_finder import find_source_sink_paths
from core.danger_func_analyzer import DangerFuncAnalyzer
from core.vulinfer import VulInfer
print('All imports OK')
"
```
Expected: `All imports OK`

- [ ] **Step 6: Run full test suite**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 -m pytest tests/ -v --tb=short
```
Expected: All tests pass.

- [ ] **Step 7: Run dry-run end-to-end**

```bash
cd /Users/yangshuangning/VscodeProjects/LIVA-main
conda run -n iotreaper python3 liva.py /tmp/fake_binary /tmp/ TestDevice --dry-run
```
Expected:
```
[Plan] Stages to run (in order): elf -> source -> sink -> danger -> taint -> infer
```

- [ ] **Step 8: Final commit**

```bash
git add -A
git commit -m "fix: macOS compatibility - verify paths, env, imports"
```

---

## Self-Review Checklist

### Spec coverage
- [x] All LLM API calls changed to relay API: Task 2 (`Chatbot`), Task 7 (`run_stage_taint` uses `[Fine-tuning]` base_url), Task 1 (config updated)
- [x] Neo4j removed: Tasks 6, 7, 8 (SimplePathFinder created, neo4j stage removed, files deleted)
- [x] IDA stage replaced with IDA-MCP: Tasks 3, 4, 5 (IDAMCPClient created, source/sink/danger stages updated)
- [x] macOS compatibility: Task 9 (Ghidra path, conda env, no Windows IPs)
- [x] Code runs on macOS: Task 9 step 5–7 verifies full import chain and dry-run

### Placeholder scan
- No TBDs, TODOs, or "implement later" present.
- All code blocks contain complete, runnable code.

### Type consistency
- `IDAMCPClient.send_multiple_libs()` returns `Dict[str, Any]` matching `WindowsIDAClient.send_multiple_libs()` output format: `{libname: {"status": 200, "resp": {func: {"code": str, "inlined_from": []}}}}`
- `find_source_sink_paths()` returns `List[Dict[str, Any]]` matching Neo4j path format consumed by `VulInfer.build_reports()`
- `Chatbot.chat()` returns `bytes` — unchanged interface
- `DangerFuncAnalyzer.__init__` parameters changed from `(service_url, token)` to `(ida_mcp_path, ida_dir)` — callers in `liva.py` updated in same task
