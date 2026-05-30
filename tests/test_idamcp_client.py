import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest


@pytest.fixture(autouse=True)
def mock_ida_mcp_imports():
    """Mock out ida-mcp-main modules so tests run without IDA installed."""
    mock_ts = MagicMock()
    mock_q = MagicMock()
    mock_ida_tools = MagicMock()
    sys.modules['tools_session'] = mock_ts
    sys.modules['ida_tools'] = mock_ida_tools
    sys.modules['ida_tools.query'] = mock_q
    # Ensure ida_tools.query points to the same mock
    mock_ida_tools.query = mock_q
    yield mock_ts, mock_q
    for mod in ['tools_session', 'ida_tools', 'ida_tools.query']:
        sys.modules.pop(mod, None)
    # Remove cached IDAMCPClient module so re-import gets fresh mocks
    sys.modules.pop('core.idanet.IDAMCPClient', None)


def _make_client(mock_ts, mock_q):
    mock_ts.analyze_binary.return_value = {"ok": True, "session_id": 42}
    mock_ts.probe_ready.return_value = {"ok": True, "ready": True}
    from core.idanet.IDAMCPClient import IDAMCPClient
    return IDAMCPClient(ida_mcp_path="/fake/ida-mcp")


def _fake_path_exists(self):
    """Return True only for /fake/... paths so non-existent paths still fail."""
    return str(self).startswith("/fake/")


def test_send_multiple_libs_returns_windows_format(mock_ida_mcp_imports):
    mock_ts, mock_q = mock_ida_mcp_imports
    mock_q.lookup_funcs.return_value = {
        "ok": True,
        "functions": [{"start_ea": "0x1234", "name": "nvram_get"}],
        "unresolved": []
    }
    mock_q.decompile.return_value = {
        "ok": True, "decompilation": "char *nvram_get(char *key) { return lookup(key); }"
    }

    client = _make_client(mock_ts, mock_q)
    with patch.object(Path, "exists", _fake_path_exists):
        result = client.send_multiple_libs(
            file_mapping={"libnvram.so": "/fake/libnvram.so"},
            funcs_by_lib={"libnvram.so": ["nvram_get"]},
        )

    assert "libnvram.so" in result
    assert result["libnvram.so"]["status"] == 200
    assert "nvram_get" in result["libnvram.so"]["resp"]
    assert "nvram_get" in result["libnvram.so"]["resp"]["nvram_get"]["code"]
    assert result["libnvram.so"]["resp"]["nvram_get"]["inlined_from"] == []


def test_decompile_addresses_returns_addr_to_code_map(mock_ida_mcp_imports):
    mock_ts, mock_q = mock_ida_mcp_imports
    mock_q.decompile.return_value = {
        "ok": True, "decompilation": "void system_wrapper() { system(cmd); }"
    }

    client = _make_client(mock_ts, mock_q)
    with patch.object(Path, "exists", _fake_path_exists):
        result = client.decompile_addresses("/fake/jhttpd", ["0x1000", "0x2000"])

    assert "0x1000" in result
    assert "system_wrapper" in result["0x1000"]
    assert "0x2000" in result


def test_lookup_not_found_gives_empty_code(mock_ida_mcp_imports):
    mock_ts, mock_q = mock_ida_mcp_imports
    mock_q.lookup_funcs.return_value = {
        "ok": True, "functions": [], "unresolved": ["unknown_func"]
    }
    mock_q.decompile.return_value = {
        "ok": True, "decompilation": ""
    }

    client = _make_client(mock_ts, mock_q)
    with patch.object(Path, "exists", _fake_path_exists):
        result = client.send_multiple_libs(
            file_mapping={"lib.so": "/fake/lib.so"},
            funcs_by_lib={"lib.so": ["unknown_func"]},
        )

    assert result["lib.so"]["resp"]["unknown_func"]["code"] == ""


def test_missing_binary_returns_error(mock_ida_mcp_imports):
    mock_ts, mock_q = mock_ida_mcp_imports
    client = _make_client(mock_ts, mock_q)
    result = client.send_multiple_libs(
        file_mapping={"lib.so": "/nonexistent/lib.so"},
        funcs_by_lib={"lib.so": ["some_func"]},
    )
    assert "error" in result["lib.so"]


def test_decompile_addresses_missing_binary_returns_empty(mock_ida_mcp_imports):
    mock_ts, mock_q = mock_ida_mcp_imports
    client = _make_client(mock_ts, mock_q)
    result = client.decompile_addresses("/nonexistent/jhttpd", ["0x1000"])
    assert result == {}
