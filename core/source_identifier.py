from config import config
from core.ghidra_analyzer import UnifiedGhidraRunner
from utils.logger_config import LoggerConfig
from utils.utils import timeit_context
from pathlib import Path
import json
from typing import List, Dict, Any, Optional
import re

class SourceIdentifier:
    def __init__(self):
        self.runner = UnifiedGhidraRunner()
        self.logger = LoggerConfig.configure_logger('SourceIdentifier')
        self.json_path: Optional[Path] = None
        self.data: Dict[str, Dict[str, str]] = {}
        
    def build_sourceidentifier_job(self):
        """
        Read job config and build a list of Ghidra analysis jobs.
        Only add jobs for libraries that are not already in the database.
        Each job is a tuple: (binary_path, script_args, main_binary).
        """
        # try:
        #     session = config.IoTReaperConfig.get_db_session(config.Base)
        #     sink_data = session.query(config.ProjectInfo).filter(config.ProjectInfo.tag == "sink").first()
        #     source_data = session.query(config.ProjectInfo).filter(config.ProjectInfo.tag == "source").first()
        #     print(sink_data.data,source_data.data)
        # except Exception as e:
        #     self.logger.error("sink source sqlite error")

        # source_list = ast.literal_eval(source_data.data)
        # sink_list = ast.literal_eval(sink_data.data)

        main_binary = f"result/{config.IoTReaperConfig.project_path}/{config.IoTReaperConfig.main_project_name}/iot_file/{config.IoTReaperConfig.main_file_name}"
        script_args = [
            "scripts/SourceIdentifier.java",
            f"result/{config.IoTReaperConfig.project_path}/{config.IoTReaperConfig.main_project_name}"
        ]
        return (main_binary, script_args, main_binary)

    def run_sourceidentifier_batch_analysis(self):
        """
        Run batch analysis jobs using Ghidra.
        """
        results = None
        job = self.build_sourceidentifier_job()
        if len(job) == 3:
            with timeit_context("run_sourceidentifier_batch_analysis"):
                results = self.runner.analyze(job)
        return results



    def load(self):
        """从指定 JSON 文件加载符号数据"""
        json_path = f"result/{config.IoTReaperConfig.project_path}/{config.IoTReaperConfig.main_project_name}/elf_parse/common_functions.json"

        path = Path(json_path)
        if not path.exists():
            raise FileNotFoundError(f"Symbol file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        self.json_path = path
        print(f"[+] Loaded {len(self.data)} libraries from {path}")

    def reload(self):
        """重新加载上一次加载的文件"""
        if not self.json_path:
            raise RuntimeError("No JSON file loaded yet. Use load(path) first.")
        self.load(self.json_path)

    # -------------------------- 查找函数 --------------------------

    def find_symbol(self, query: str, exact: bool = True) -> List[Dict[str, str]]:
        """查找单个符号"""
        if not self.data:
            raise RuntimeError("No data loaded. Call load() first.")
        results = []
        for libname, symtab in self.data.items():
            for func_name, addr in symtab.items():
                if exact and func_name == query:
                    results.append({"lib": libname, "func": func_name, "addr": addr})
                elif not exact and query in func_name:
                    results.append({"lib": libname, "func": func_name, "addr": addr})
        return results

    def find_symbols_batch(self, queries: List[str], exact: bool = True) -> Dict[str, List[Dict[str, str]]]:
        """批量查找多个符号"""
        if not self.data:
            raise RuntimeError("No data loaded. Call load() first.")
        return {q: self.find_symbol(q, exact=exact) for q in queries}
    
    def convert_name(self, name: str) -> str:
        return re.sub(r'^FUN_0*([0-9a-fA-F]+)$', lambda m: f"sub_{m.group(1)}", name)

    def find_by_lib_grouped(self, queries: List[str], exact: bool = True) -> Dict[str, List[str]]:
        """
        批量查找多个函数，并以库名为 key 分组：
        返回 { lib_name: [func1, func2, ...] }
        """
        if not self.data:
            raise RuntimeError("No data loaded. Call load() first.")

        grouped: Dict[str, List[str]] = {}
        for q in queries:
            # 判断是否是 FUN_xxxxxx 格式
            if re.fullmatch(r"FUN_[0-9a-fA-F]{6,10}", q):
                # 如果是这种形式，则直接加入 httpd 键
                grouped.setdefault(config.IoTReaperConfig.main_file_name, []).append(self.convert_name(q))
            else:
                # 否则调用 find_symbol
                matches = self.find_symbol(q, exact=exact)
                if matches == []:
                    grouped.setdefault(config.IoTReaperConfig.main_file_name, []).append(q)
                    continue
                for m in matches:
                    lib = m["lib"]
                    func = m["func"]
                    grouped.setdefault(lib, []).append(func)

        return grouped
    
    @staticmethod
    def parse_call_report_file() -> Dict[str, int]:
        """
        解析类似你贴的这种文本报告，抽取 {函数名: 调用次数num}

        规则：
          - 每个函数块以 "Call: <name>" 开头
          - 下面几行会出现 "num: <次数>"
        我们把这两行绑定起来。

        返回 dict，例如:
        {
            "httpd_get_parm": 537,
            "nvram_get": 371,
            ...
        }
        """
        report_path = f"result/{config.IoTReaperConfig.project_path}/{config.IoTReaperConfig.main_project_name}/strings_calls.txt"

        path = Path(report_path)
        if not path.exists():
            raise FileNotFoundError(f"Report file not found: {path}")

        text = path.read_text(encoding="utf-8", errors="replace")

        # 我们逐块匹配：
        # 思路：用正则找到所有 "Call: ... num: ..." 对
        # 用非贪婪匹配跨行.
        pattern = re.compile(
            r"Call:\s*(?P<func>\S+).*?^\s*num:\s*(?P<num>\d+)",
            re.MULTILINE | re.DOTALL
        )

        results: Dict[str, int] = {}
        for m in pattern.finditer(text):
            func_name = m.group("func")
            num_str = m.group("num")
            try:
                count = int(num_str)
            except ValueError:
                continue
            if int(num_str) > 10:
                results[func_name] = count

        return results
    # -------------------------- 输出辅助 --------------------------

    def pretty_print(self, result: Dict[str, List[Dict[str, str]]]):
        """打印结果"""
        print(json.dumps(result, indent=2, ensure_ascii=False))
