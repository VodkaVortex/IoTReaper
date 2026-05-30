import sys
import time
import logging
from pathlib import Path
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class IDAMCPClient:
    """
    Drop-in replacement for WindowsIDAClient.
    Uses local ida-mcp-main to decompile via IDA Pro on macOS.
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

        if self.ida_mcp_path not in sys.path:
            sys.path.insert(0, self.ida_mcp_path)

        import tools_session as _ts
        import ida_tools.query as _q
        self._ts = _ts
        self._q = _q

    def _get_or_create_session(self, binary_path: str) -> int:
        if binary_path in self._session_cache:
            return self._session_cache[binary_path]

        result = self._ts.analyze_binary(binary_path=binary_path, ida_dir=self.ida_dir)
        if not result.get("ok"):
            raise RuntimeError(f"IDA-MCP analyze_binary failed for {binary_path}: {result.get('error', result)}")
        session_id: int = result["session_id"]
        logger.info("IDA session %d created for %s, waiting for ready...", session_id, binary_path)

        deadline = time.time() + self.probe_timeout_sec
        while time.time() < deadline:
            status = self._ts.probe_ready(session_id, timeout_sec=self.probe_interval_sec)
            if status.get("ready"):
                logger.info("IDA session %d ready", session_id)
                self._session_cache[binary_path] = session_id
                return session_id
            logger.debug("session %d not ready: %s", session_id, status.get("message", ""))
            time.sleep(self.probe_interval_sec)

        raise TimeoutError(f"IDA session {session_id} did not become ready within {self.probe_timeout_sec}s")

    def _decompile_one(self, session_id: int, func_name: str) -> str:
        lookup = self._q.lookup_funcs(session_id, queries=[func_name])
        if not lookup.get("ok"):
            logger.warning("lookup_funcs failed for %s: %s", func_name, lookup.get("error"))
            return ""
        funcs = lookup.get("functions", [])
        if not funcs:
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
        Drop-in for WindowsIDAClient.send_multiple_libs.
        Returns: {libname: {"status": 200, "resp": {func: {"code": str, "inlined_from": []}}}}
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

    def decompile_addresses(self, binary_path: str, addresses: List[str]) -> Dict[str, str]:
        """
        Decompile functions by address (used in danger stage).
        Returns: {"0x1000": "<C pseudocode>", ...}
        """
        if not Path(binary_path).exists():
            logger.warning("Binary not found for decompile_addresses: %s", binary_path)
            return {}
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
        try:
            self._ts.end_all_sessions()
            logger.info("Ended all IDA sessions")
        except Exception as exc:
            logger.warning("Failed to end all sessions: %s", exc)
        self._session_cache.clear()
