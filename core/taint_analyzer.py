from concurrent.futures import ThreadPoolExecutor, TimeoutError
import time
from typing import List, Optional, Dict, Any, Tuple
import json
from pathlib import Path
from typing import Any, Dict, List
from config import config
import json

class TaintAnalyzer:
    """
    Wrapper for robust interactions with an OpenAI-compatible Chat Completions API.
    - Supports timeout via a worker thread (so we can cancel on long calls)
    - Retries with exponential backoff on transient failures
    - Configurable base messages (system+few-shot), model, temperature, max_tokens
    - Optional streaming (returns concatenated text)
    """

    def __init__(
        self,
        client,
        *,
        model: str = "Liva",
        temperature: float = 0.8,
        max_tokens: int = 8196,
        timeout: int = 70,
        retries: int = 2,
        retry_backoff: float = 1.5,
        max_workers: int = 1
    ):
        """
        :param client: An initialized OpenAI client (openai.OpenAI(...))
        :param model:  Model name
        :param temperature: Sampling temperature
        :param max_tokens: Max tokens in the completion
        :param timeout: Per-request timeout (seconds)
        :param retries: Number of retries on failure (total attempts = 1 + retries)
        :param retry_backoff: Exponential backoff base (seconds) between retries
        :param max_workers: Thread pool workers for enforcing timeout
        """
        self.client = client
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.retries = retries
        self.retry_backoff = retry_backoff
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    # ---------- Message templates ----------

    def build_base_messages(self) -> List[Dict[str, str]]:
        """
        Build the shared base messages (system + few-shot).
        You can adjust these prompts in one place.
        """
        return [
            {
                "role": "system",
                "content": (
                    "你在函数参数传递分析方面是专家，帮我按照训练数据格式进行分析，"
                ),
            },
            {"role": "user", "content": "我先给你个分析样样例，你在输出结果时不要分析过程只要结果，就是直接给出参数映射关系结构"},
            {"role": "assistant", "content": "ok, 请输入"},
            {
                "role": "user",
                "content": (
                    "分析doSystemCmd 到 system 函数的参数映射关系结构\n\n"
                    " 1: int doSystemCmd(char *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)\n"
                    " 2: {\n 3: int iVar1;\n 4: char acStack_880 [2048];\n 5: stat sStack_80;\n 6: undefined4 *local_28;\n"
                    " 7: int local_24;\n 8: undefined4 uStack_c;\n 9: undefined4 uStack_8;\n10: undefined4 uStack_4;\n"
                    "11:\n12: local_24 = 0;\n13: uStack_c = param_2;\n14: uStack_8 = param_3;\n15: uStack_4 = param_4;\n"
                    "16: memset(acStack_880,0,0x800);\n17: memset(acStack_880,0,4);\n"
                    "18: local_28 = &uStack_c;\n19: local_24 = vsnprintf(acStack_880,0x800,param_1,local_28);\n"
                    "20: iVar1 = stat(\"/var/syscmd\",&sStack_80);\n21: if (iVar1 != -1) {\n22: puts(acStack_880);\n23: }\n"
                    "24: iVar1 = system(acStack_880);\n25: return iVar1;\n26: }\n27:"
                ),
            },
            {
                "role": "assistant",
                "content": (
                    "参数映射关系结构为 {\"doSystemCmd\": (\"system\", {\"1\": [1,2,3,4]}, \"line:24\", "
                    "\"system(acStack_880);\")}"
                ),
            },
            {
                "role": "user",
                "content": (
                    "分析 generate_config 到 sprintf,save_config 函数的参数映射关系结构\n\n"
                    " 1: int generate_config()\n 2: {\n 3:     char username[128];\n"
                    " 4:     char config_data[512];\n 5:     char config_file[256];\n"
                    " 6:\n 7:     cgiFormString(\"username\", username, sizeof(username));\n"
                    " 8:     cgiFormString(\"config_data\", config_data, sizeof(config_data));\n"
                    " 9:\n10:     sprintf(config_file, \"/etc/config/%s.cfg\", username);\n"
                    "11:     save_config(config_file, config_data);\n12:\n13:     return 0;\n14: }"
                ),
            },
            {
                "role": "assistant",
                "content": (
                    "参数映射关系结构为 {\"generate_config\": [(\"sprintf\", {\"2\": "
                    "\"cgiFormString('username', username, sizeof(username))\"}, \"line:10\", "
                    "\"sprintf(config_file, \\\"/etc/config/%s.cfg\\\", username);\"),(\"save_config\", {\"2\":\"cgiFormString('config_data', config_data, sizeof(config_data))\"})]}"
                ),
            },
        ]

    def build_request_messages(
        self, input_text: str, extra_messages: Optional[List[Dict[str, str]]] = None
    ) -> List[Dict[str, str]]:
        """
        Compose the message list for a single request.
        """
        msgs = extra_messages[:] if extra_messages else self.build_base_messages()
        msgs.append({
            "role": "user",
            "content": "请根据分析规则，分析下面的代码的参数传递结构：\n" + input_text
        })
        return msgs

    # ---------- Core interaction ----------

    def _create_completion(self, messages: List[Dict[str, str]], stream: bool) -> str:
        """
        Low-level API call. If stream=True, concatenates streamed chunks into a single string.
        """
        if not stream:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=False,
            )
            return resp.choices[0].message.content or ""

        # stream=True
        collected = []
        with self.client.chat.completions.stream(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        ) as stream_resp:
            for event in stream_resp:
                # The python SDK might expose chunks differently across versions;
                # we simply accumulate text fragments if present.
                try:
                    delta = getattr(event, "delta", None)
                    if delta and getattr(delta, "content", None):
                        collected.append(delta.content)
                except Exception:
                    # Fallback: try-common fields
                    try:
                        if event.choices and event.choices[0].delta and event.choices[0].delta.get("content"):
                            collected.append(event.choices[0].delta["content"])
                    except Exception:
                        pass
        return "".join(collected)

    def ask_gpt(
        self,
        input_text: str,
        *,
        extra_messages: Optional[List[Dict[str, str]]] = None,
        stream: bool = False,
        timeout: Optional[int] = None,
        retries: Optional[int] = None,
    ) -> str:
        """
        Public method: send one code snippet to the model and return the assistant text.

        :param input_text: The code text to analyze
        :param extra_messages: Optional override/extend base messages
        :param stream: If True, use streaming API and return concatenated text
        :param timeout: Override default timeout for this call
        :param retries: Override default retries for this call
        :return: Assistant reply text (may be empty string on rare cases)
        :raises TimeoutError on timeout; raises last exception on other failures after retries
        """
        messages = self.build_request_messages(input_text, extra_messages)
        attempt_retries = self.retries if retries is None else max(0, int(retries))
        per_timeout = self.timeout if timeout is None else max(1, int(timeout))

        last_err: Optional[Exception] = None
        for attempt in range(attempt_retries + 1):
            try:
                future = self.executor.submit(self._create_completion, messages, stream)
                return future.result(timeout=per_timeout)
            except TimeoutError as te:
                last_err = te
                # Cancel the in-flight task
                future.cancel()
                if attempt < attempt_retries:
                    time.sleep(self.retry_backoff ** (attempt + 1))
                # else:
                #     raise
            except Exception as e:
                last_err = e
                if attempt < attempt_retries:
                    time.sleep(self.retry_backoff ** (attempt + 1))
                # else:
                #     raise
        # Should not reach here
        raise last_err or RuntimeError("Unknown error in ask_gpt()")


    @classmethod
    def load_preprocess_entries(self) -> Tuple[List[str], str, Dict[str, str]]:
        """
        读取 preprocess_gpt_data.json，生成段落：
        分析 <parent_name> 到 <callee> 函数的参数映射关系结构
        <code block>

        Returns:
        - entries: list[str]，每个 paragraph
        - combined_text: str，所有条目拼接
        - entry_vars: dict[str, str]，形式如 {"entry_1": paragraph1, "entry_2": paragraph2, ...}
        """
        # Resolve JSON path
        base_dir = Path(f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}")
        json_path = base_dir / "preprocess_gpt_data.json"

        # Load JSON
        with json_path.open("r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)

        results = data.get("results", [])
        entries: List[str] = []
        entry_vars: Dict[str, str] = {}

        for item in results:
            parent_name: str = item.get("parent_name", "UNKNOWN_FUNC")
            code: str = item.get("code", "").rstrip("\n")

            # Prefer 'analysis' to get callees; fall back to 'targets'
            callees: List[str] = []
            for an in item.get("analysis", []):
                if isinstance(an, list) and an:
                    callee = an[0]
                    if isinstance(callee, str):
                        callees.append(callee)

            if not callees:
                callees = [t for t in item.get("targets", []) if isinstance(t, str)]

            for callee in callees:
                header = f"分析 {parent_name} 到 {callee} 函数的参数映射关系结构\n\n"
                paragraph = header + code + ("\n" if not code.endswith("\n") else "")
                entries.append(paragraph)

        # 拼接保存
        combined_text = "\n\n".join(entries)
        out_path = base_dir / "sendtogpt.txt"
        out_path.write_text(combined_text, encoding="utf-8")

        # 建立 entry_vars，编号形式 entry_1, entry_2, ...
        for idx, para in enumerate(entries, start=1):
            entry_vars[f"entry_{idx}"] = para

        return entries, combined_text, entry_vars
    
    @classmethod
    def gpt_preprocess(self) -> Path:
        """
        Preprocesses danger function compile results for GPT-based analysis.
        
        Steps:
        1. Reads the `danger_func_compile.json` file from the project result directory.
        2. Iterates over each element in the "data" array.
        3. Uses `decompiled_c` as `code_text` and `child_names` as analysis targets.
        4. Calls `DecompilerCallAnalyzer.analyze` to extract function call details.
        5. Saves all processed results into `preprocess_gpt_data.json` in the same directory.
        
        Returns:
            Path: The path to the output JSON file.
        """
        # Define input/output file paths
        base_dir = Path(f"result/{config.LivaConfig.project_path}/{config.LivaConfig.main_project_name}")
        in_path = base_dir / "parent_child_calls_ida_decompile.json"
        out_path = base_dir / "preprocess_gpt_data.json"
        base_dir.mkdir(parents=True, exist_ok=True)

        # Validate input file existence
        if not in_path.exists():
            raise FileNotFoundError(f"Input file not found: {in_path}")

        # Load input JSON
        with in_path.open("r", encoding="utf-8") as f:
            payload = json.load(f)

        data: List[Dict[str, Any]] = payload.get("data", [])
        results: List[Dict[str, Any]] = []
        errors: List[Dict[str, Any]] = []

        # Process each entry in `data`
        for idx, item in enumerate(data):
            parent_name = item.get("parent_name")
            parent_address = item.get("parent_address")
            code_text: str = item.get("decompiled_c") or ""

            # Extract and clean `child_names` as analysis targets
            raw_targets = item.get("child_names") or []
            targets = [t for t in dict.fromkeys([str(t).strip() for t in raw_targets]) if t]

            # Skip if no code or no targets
            if not code_text.strip():
                errors.append({
                    "index": idx,
                    "parent_name": parent_name,
                    "parent_address": parent_address,
                    "reason": "Empty decompiled_c"
                })
                continue
            if not targets:
                errors.append({
                    "index": idx,
                    "parent_name": parent_name,
                    "parent_address": parent_address,
                    "reason": "Empty child_names"
                })
                continue

            # Run analysis
            try:
                analyze_result = DecompilerCallAnalyzer.analyze(code_text, targets)
            except Exception as e:
                errors.append({
                    "index": idx,
                    "parent_name": parent_name,
                    "parent_address": parent_address,
                    "reason": f"Analysis error: {type(e).__name__}: {e}"
                })
                continue

            # Append analysis results
            results.append({
                "parent_name": parent_name,
                "parent_address": parent_address,
                "targets": targets,
                "code": code_text,
                "analysis": analyze_result
            })

        # Build output structure
        output_payload = {
            "meta": {
                "project_path": config.LivaConfig.project_path,
                "main_project_name": config.LivaConfig.main_project_name,
                "source_file": str(in_path),
                "total_items": len(data),
                "analyzed": len(results),
                "skipped_or_errors": len(errors),
            },
            "results": results,
            "errors": errors
        }

        # Save output JSON
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(output_payload, f, ensure_ascii=False, indent=2)

        return out_path


import re
from typing import List, Dict, Tuple, Iterable

class DecompilerCallAnalyzer:
    """
    One-shot analyzer for decompiled C-like text.
    Call the class method `analyze(code, targets, ...)` each time you need results.
    Output: List[(func_name, (has_dynamic_args, has_percent_s, "line:NNN"))]
    """

    # --- Regexes (compiled once) --- #
    CALL_RE = re.compile(r'(?P<name>[A-Za-z_]\w*)\s*\(\s*(?P<args>[^;]*?)\s*\)\s*;', re.S)
    FUNC_HEAD_RE = re.compile(r'^[ \t]*[A-Za-z_]\w*\s+[A-Za-z_]\w*\s*\((?P<params>[^)]*)\)', re.M)
    ASSIGN_RE = re.compile(r'(?P<lhs>[A-Za-z_]\w*(?:\.\w+|(?:\._\d+_\d+_)?)?)\s*=\s*(?P<rhs>[^;]+);')
    STRING_RE = re.compile(r'"([^"\\]|\\.)*"')
    NUM_RE = re.compile(r'^(?:0x[0-9a-fA-F]+|\d+)$')
    CHAR_RE = re.compile(r"^'(?:\\.|[^'])'$")
    IDENT_RE = re.compile(r'[A-Za-z_]\w*')
    FUNC_CALL_IN_ARG_RE = re.compile(r'([A-Za-z_]\w*)\s*\(')
    # Accept "  47 | ..." or "  47: ..."
    LINE_PREFIX_RE = re.compile(r'^\s*(\d+)\s*(?:\||:)\s*')

    # ============ Public API ============ #
    @classmethod
    def analyze(
        cls,
        code: str,
        targets: List[str],
        *,
        # Strict mode: only string/numeric literals are "fixed".
        # You can widen the definition via the flags below.
        treat_const_expr_as_fixed: bool = False,
        treat_local_addr_const_as_fixed: bool = False,
    ) -> List[Tuple[str, Tuple[bool, bool, str]]]:
        """
        Analyze `code` and return tuples:
        [(func_name, (has_dynamic_args, has_percent_s, "line:NNN")), ...]

        has_dynamic_args: True if exists an arg that is NOT a numeric/string literal
                          (False if all args are literals or there are no args)
        has_percent_s:    True if any string literal arg contains "%s"
        line:             decompiler's own line number prefix (NNN | / NNN:)
        """
        line_index = cls._build_line_index(code)
        const_only = cls._build_const_only_map([ln for _, ln, _ in line_index])
        params = cls._parse_params(code)
        target_set = set(targets)

        def is_fixed_literal(kind: str) -> bool:
            if kind in ("STRING_LITERAL", "NUM_LITERAL"):
                return True
            if treat_local_addr_const_as_fixed and kind == "LOCAL_ADDR_CONST":
                return True
            if treat_const_expr_as_fixed and kind == "CONST_EXPR":
                return True
            return False

        results: List[Tuple[str, Tuple[bool, bool, str]]] = []
        for m in cls.CALL_RE.finditer(code):
            name = m.group('name')
            if name not in target_set:
                continue
            args = cls._split_args(m.group('args'))
            classified = [cls._classify_arg(a, params, const_only) for a in args]

            has_dynamic = False if not classified else not all(is_fixed_literal(k) for k, _ in classified)
            has_percent_s = any('%s' in cls._strip_casts(expr) for k, expr in classified if k == "STRING_LITERAL")
            deco_line = cls._find_decompiler_line_for_pos(line_index, m.start())

            results.append((name, (has_dynamic, has_percent_s, deco_line)))
        return results

    @classmethod
    def format_results(cls, results: Iterable[Tuple[str, Tuple[bool, bool, str]]]) -> List[str]:
        """Pretty formatting helper."""
        out = []
        for name, (dyn, fmt, line) in results:
            out.append(f'{name}: (has_dynamic_args={dyn}, has_percent_s={fmt}, "{line}")')
        return out

    # ============ Internals ============ #
    @classmethod
    def _tokenize_idents(cls, expr: str):
        expr_ = cls.STRING_RE.sub('"STR"', expr)
        return cls.IDENT_RE.findall(expr_)

    @classmethod
    def _is_string_literal(cls, expr: str) -> bool:
        return bool(cls.STRING_RE.fullmatch(expr.strip()))

    @classmethod
    def _is_numeric_literal(cls, expr: str) -> bool:
        s = expr.strip()
        return bool(cls.NUM_RE.match(s)) or bool(cls.CHAR_RE.match(s))

    @classmethod
    def _has_func_call(cls, expr: str) -> bool:
        return bool(cls.FUNC_CALL_IN_ARG_RE.search(expr))

    @classmethod
    def _strip_casts(cls, expr: str) -> str:
        return re.sub(r'\([ \t]*[A-Za-z_][\w\s\*]*\)', '', expr).strip()

    @classmethod
    def _split_args(cls, argstr: str) -> List[str]:
        args, cur, level = [], [], 0
        for ch in argstr:
            if ch == '(':
                level += 1
            elif ch == ')':
                level -= 1
            if ch == ',' and level == 0:
                args.append(''.join(cur).strip()); cur = []
            else:
                cur.append(ch)
        tail = ''.join(cur).strip()
        if tail:
            args.append(tail)
        return args

    @classmethod
    def _parse_params(cls, code: str) -> List[str]:
        m = cls.FUNC_HEAD_RE.search(code)
        if not m:
            return []
        p = m.group('params').strip()
        if not p or p == 'void':
            return []
        out = []
        for part in cls._split_args(p):
            ids = cls.IDENT_RE.findall(part)
            if ids:
                out.append(ids[-1])
        return out

    @classmethod
    def _build_const_only_map(cls, lines: List[str]) -> Dict[str, bool]:
        """Heuristic: mark local_X as True if only built from literals/ops/CONCAT/local_ slices."""
        const_only: Dict[str, bool] = {}
        for ln in lines:
            for am in cls.ASSIGN_RE.finditer(ln):
                lhs = am.group('lhs').strip()
                rhs = am.group('rhs').strip()
                base = lhs.split('.')[0]
                if not base.startswith('local_'):
                    continue
                rhs_no_cast = cls._strip_casts(rhs)
                if cls._has_func_call(rhs_no_cast):
                    const_only[base] = False
                    continue
                ids = [i for i in cls._tokenize_idents(rhs_no_cast) if i not in ('CONCAT','CONCAT22','CONCAT12')]
                nonconst = [i for i in ids if not i.startswith('local_')]
                if cls._is_numeric_literal(rhs_no_cast) or cls._is_string_literal(rhs_no_cast):
                    const_only.setdefault(base, True); continue
                if not nonconst:
                    const_only.setdefault(base, True); continue
                const_only[base] = False
        return const_only

    @classmethod
    def _classify_arg(cls, expr: str, params: List[str], const_only_locals: Dict[str, bool]) -> Tuple[str, str]:
        """
        Return (class, raw_expr). Classes:
          STRING_LITERAL, NUM_LITERAL, PARAM_REFERENCE,
          LOCAL_ADDR_CONST, LOCAL_ADDR_UNKNOWN,
          FROM_FUNC_CALL, CONST_EXPR, VAR_EXPR
        """
        raw = expr.strip()
        expr = cls._strip_casts(raw)
        if cls._is_string_literal(expr): return ("STRING_LITERAL", raw)
        if cls._is_numeric_literal(expr): return ("NUM_LITERAL", raw)
        for p in params:
            if re.search(rf'\b{re.escape(p)}\b', expr):
                return ("PARAM_REFERENCE", raw)
        amp_local = re.match(r'^[&\( ]*\s*(?:[A-Za-z_][\w\s\*\(\)]*\*\s*)?(?:\(\s*)?&\s*(local_\w+)', expr)
        if amp_local:
            base = amp_local.group(1)
            return ("LOCAL_ADDR_CONST" if const_only_locals.get(base, False) else "LOCAL_ADDR_UNKNOWN", raw)
        if cls._has_func_call(expr): return ("FROM_FUNC_CALL", raw)
        expr_no_str = cls.STRING_RE.sub('STR', expr)
        tokens = cls._tokenize_idents(expr_no_str)
        allow = {'CONCAT','CONCAT22','CONCAT12'}
        unknown = [t for t in tokens if t not in allow and not t.startswith('local_')]
        return ("CONST_EXPR" if not unknown else "VAR_EXPR", raw)

    # --- Decompiler line mapping --- #
    @classmethod
    def _build_line_index(cls, code: str):
        """Return [(start_offset, full_line_text, deco_line_num_or_None)]."""
        lines = code.splitlines(keepends=True)
        idx = []
        offset = 0
        for ln in lines:
            m = cls.LINE_PREFIX_RE.match(ln.rstrip('\n').rstrip('\r'))
            deco = m.group(1) if m else None
            idx.append((offset, ln, deco))
            offset += len(ln)
        return idx

    @staticmethod
    def _find_decompiler_line_for_pos(line_index, pos: int) -> str:
        """Return 'line:NNN' for the line containing byte offset `pos`."""
        for i in range(len(line_index)):
            start, ln, deco = line_index[i]
            end = line_index[i+1][0] if i+1 < len(line_index) else 10**18
            if start <= pos < end:
                return f"line:{deco}" if deco is not None else "line:?"
        return "line:?"

# ============ Example ============ #
if __name__ == "__main__":
    code_text = r'''
 1:
 2: void FUN_00018f54(void)
 3:
 4: {
 ...
86:   sprintf(acStack_178,"@%s",acStack_78);
91:   fprintf(cgiOut,"%d</ftp>",uVar4);
92:   safe_system("/dev/null",0,"makedav",&DAT_000232f0,acStack_178,0);
    '''
    targets = ["sprintf", "safe_system", "fprintf", "httpd_send_mime_file", "do_something"]

    results = DecompilerCallAnalyzer.analyze(code_text, targets)
    for line in DecompilerCallAnalyzer.format_results(results):
        print(line)

