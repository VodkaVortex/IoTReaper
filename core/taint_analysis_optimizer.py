#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
污点分析代码优化工具（增强版，含常量传播 / 写缓冲区建模 / return puts 修复 / 屏蔽 printf 与 xx）
- 反向污点分析：从危险函数开始回溯相关参数传递路径
- 常量传播：识别“变量只是搬运固定字符串/常量，再传给函数”的情况，并删除这些调用/赋值行
- 写缓冲区建模：识别 sprintf/snprintf/strcpy/strcat/memcpy 等把源数据写入目的缓冲区的调用，
  为 dest 建立依赖边，从而能从 system(dest) 继续追踪到上游变量
- 修正：return puts("...") 等固定参数调用优先删除，不再因结构行保留而漏删
- 新增：无条件删除包含 printf(...) 与 xx(...) 的行（REMOVED (BANNED_FUNC)）
"""

import re
from typing import Set, Dict, List, Tuple, Optional
from collections import defaultdict, deque


class TaintAnalysisOptimizer:
    def __init__(self):
        # 危险函数列表（用于确定污点源等；不等同于删除列表）
        self.dangerous_functions = {
            'system', 'popen', 'exec', 'execv', 'execve', 'execl', 'execlp',
            'sprintf', 'strcpy', 'strcat', 'gets', 'scanf', 'wsprintf'
        }

        # —— 无条件删除的函数名（不论是否必要/结构性/固定参数） —— #
        self.banned_functions: Set[str] = {'printf', 'memset', ''}

        # 依赖图：lhs_var -> {rhs_var1, ...}
        self.dependency_graph: Dict[str, Set[str]] = defaultdict(set)

        # 源码缓存
        self.code_lines: List[str] = []

        # 需要保留的行号
        self.required_lines: Set[int] = set()

        # 变量定义/使用位置
        self.var_definitions: Dict[str, Set[int]] = defaultdict(set)
        self.var_usages: Dict[str, Set[int]] = defaultdict(set)

        # 函数调用：行号 -> (函数名, 参数列表)
        self.function_calls: Dict[int, Tuple[str, List[str]]] = {}

        # 常量赋值与固定参数调用
        self.constant_assignments: Set[int] = set()
        self.fixed_param_calls: Set[int] = set()

        # 常量传播：赋值记录、RHS、纯常量变量
        self.assignments_by_var: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
        self.rhs_by_line: Dict[int, str] = {}
        self.pure_constant_vars: Set[str] = set()

    # -------------------- 解析主流程 --------------------

    def parse_c_code(self, code: str) -> None:
        """解析C代码，提取依赖关系/调用，并做常量传播标注"""
        # 重置
        self.dependency_graph.clear()
        self.code_lines = code.split('\n')
        self.required_lines.clear()
        self.var_definitions.clear()
        self.var_usages.clear()
        self.function_calls.clear()
        self.constant_assignments.clear()
        self.fixed_param_calls.clear()
        self.assignments_by_var.clear()
        self.rhs_by_line.clear()
        self.pure_constant_vars.clear()

        for line_num, raw_line in enumerate(self.code_lines):
            line = raw_line.strip()
            if not line or line.startswith('//') or line.startswith('/*'):
                continue
            self._parse_assignment(line, line_num)
            self._parse_function_call(line, line_num)
            self._parse_declaration(line, line_num)
            self._parse_condition(line, line_num)

        # 常量传播
        self._compute_pure_constant_vars()
        self._mark_fixed_param_calls_after_propagation()

    # -------------------- 解析子功能 --------------------

    def _record_assignment(self, var: str, expr: str, line_num: int) -> None:
        expr = expr.strip().rstrip(';')
        self.assignments_by_var[var].append((line_num, expr))
        self.rhs_by_line[line_num] = expr

    def _parse_assignment(self, line: str, line_num: int) -> None:
        assignment_pattern = r'(\w+)\s*=\s*(.+);?'
        match = re.match(assignment_pattern, line)
        if match:
            var_name = match.group(1)
            expression = match.group(2)
            self._record_assignment(var_name, expression, line_num)

            if self._is_constant_expression(expression):
                self.constant_assignments.add(line_num)
                self.var_definitions[var_name].add(line_num)
                return

            self.var_definitions[var_name].add(line_num)
            used_vars = self._extract_variables_from_expression(expression)
            for used_var in used_vars:
                self.var_usages[used_var].add(line_num)
                self.dependency_graph[var_name].add(used_var)

    def _parse_function_call(self, line: str, line_num: int) -> None:
        func_pattern = r'(\w+)\s*\(([^)]*)\)'
        matches = re.findall(func_pattern, line)

        for func_name, args_str in matches:
            args: List[str] = []
            if args_str.strip():
                args = [arg.strip() for arg in self._split_args(args_str)]

            # 先做“原生常量”判断（不含传播）
            all_constant = True
            for arg in args:
                if not self._is_constant_expression(arg):
                    all_constant = False
                    break
            if all_constant:
                self.fixed_param_calls.add(line_num)
            else:
                # 记录各参数中的变量使用
                for arg in args:
                    used_vars = self._extract_variables_from_expression(arg)
                    for var in used_vars:
                        self.var_usages[var].add(line_num)

            self.function_calls[line_num] = (func_name, args)

            # —— 写缓冲区建模：根据函数原型把首参视为目的缓冲区，建立依赖 —— #
            self._model_write_effect(func_name, args, line_num)

    def _split_args(self, args_str: str) -> List[str]:
        """对参数串进行浅层切分，考虑引号与括号深度（避免逗号误切）。"""
        args = []
        cur = []
        depth = 0
        in_s = False
        in_d = False
        esc = False
        for ch in args_str:
            cur.append(ch)
            if esc:
                esc = False
                continue
            if ch == '\\':
                esc = True
                continue
            if in_s:
                if ch == "'":
                    in_s = False
                continue
            if in_d:
                if ch == '"':
                    in_d = False
                continue
            if ch == "'":
                in_s = True
                continue
            if ch == '"':
                in_d = True
                continue
            if ch == '(':
                depth += 1
                continue
            if ch == ')':
                if depth > 0:
                    depth -= 1
                continue
            if ch == ',' and depth == 0:
                args.append(''.join(cur[:-1]).strip())
                cur = []
        if cur:
            args.append(''.join(cur).strip())
        return args

    def _parse_declaration(self, line: str, line_num: int) -> None:
        decl_patterns = [
            r'(?:const\s+)?(?:char|int|float|double|void)\s*\*?\s*(\w+)\s*=\s*(.+);',
            r'(?:const\s+)?(?:char|int|float|double|void)\s*\*?\s*(\w+)\s*;',
            r'(?:const\s+)?(?:char|int|float|double|void)\s+(\w+)\[.*?\]\s*=?\s*(.*);'
        ]
        for pattern in decl_patterns:
            match = re.match(pattern, line)
            if match:
                var_name = match.group(1)
                self.var_definitions[var_name].add(line_num)
                if len(match.groups()) > 1 and match.group(2):
                    init_expr = match.group(2).strip()
                    if init_expr:
                        self._record_assignment(var_name, init_expr, line_num)
                        used_vars = self._extract_variables_from_expression(init_expr)
                        for var in used_vars:
                            self.var_usages[var].add(line_num)
                            self.dependency_graph[var_name].add(var)
                        if self._is_constant_expression(init_expr):
                            self.constant_assignments.add(line_num)

    def _parse_condition(self, line: str, line_num: int) -> None:
        condition_patterns = [
            r'if\s*\(([^)]+)\)',
            r'while\s*\(([^)]+)\)',
            r'for\s*\([^;]*;([^;]*);[^)]*\)'
        ]
        for pattern in condition_patterns:
            match = re.search(pattern, line)
            if match:
                condition = match.group(1)
                used_vars = self._extract_variables_from_expression(condition)
                for var in used_vars:
                    self.var_usages[var].add(line_num)

    # -------------------- 写缓冲区建模 --------------------

    def _first_identifier(self, expr: str) -> Optional[str]:
        m = re.search(r'\b[a-zA-Z_]\w*\b', expr)
        return m.group(0) if m else None

    def _model_write_effect(self, func_name: str, args: List[str], line_num: int) -> None:
        """为常见的写缓冲区函数建立依赖：dest <- {sources...}，并把该行记作 dest 的一次“定义”"""
        if not args:
            return
        name = func_name.lower()

        def add_edges(dest_expr: str, src_exprs: List[str]) -> None:
            dest_var = self._first_identifier(dest_expr)
            if not dest_var:
                return
            # 该调用行视作 dest 的一次“定义”（值更新）
            self.var_definitions[dest_var].add(line_num)
            # 源变量 -> 用于依赖和使用记录
            for se in src_exprs:
                for v in self._extract_variables_from_expression(se):
                    self.var_usages[v].add(line_num)
                    self.dependency_graph[dest_var].add(v)

        if name in ('sprintf', 'vsprintf'):
            if len(args) >= 2:
                # dest = args[0]; format = args[1]; sources = args[2:]
                add_edges(args[0], args[2:])
        elif name in ('snprintf', 'vsnprintf'):
            if len(args) >= 3:
                # dest = args[0]; size = args[1]; format = args[2]; sources = args[3:]
                add_edges(args[0], args[3:])
        elif name in ('strcpy', 'strncpy', 'strcat', 'strncat', 'memcpy', 'memmove'):
            if len(args) >= 2:
                # dest = args[0]; src = args[1]
                add_edges(args[0], [args[1]])
        # memset 不携带数据来源（或来源常量），通常不建立依赖

    # -------------------- 表达式与常量判定 --------------------

    def _contains_function_call(self, expr: str) -> bool:
        return bool(re.search(r'\b\w+\s*\(', expr))

    def _strip_literals_and_ops(self, expr: str) -> str:
        s = expr
        s = re.sub(r'"[^"]*"', '', s)
        s = re.sub(r"'[^']*'", '', s)
        s = re.sub(r'\b0[xX][0-9a-fA-F]+\b', '', s)
        s = re.sub(r'\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b', '', s)
        s = re.sub(r'\b[A-Z_][A-Z0-9_]*\b', '', s)
        s = re.sub(r'[\+\-\*/%&\|\^~<>=!\?\:\(\)\[\]\{\},\s]', '', s)
        return s

    def _expr_identifiers(self, expr: str) -> Set[str]:
        e = re.sub(r'"[^"]*"|\'[^\']*\'', '', expr)
        e = re.sub(r'\b0[xX][0-9a-fA-F]+\b', '', e)
        e = re.sub(r'\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b', '', e)
        while True:
            old = e
            e = re.sub(r'\b\w+\s*\([^()]*\)', '', e)
            if e == old:
                break
        ids = set(re.findall(r'\b[a-zA-Z_]\w*\b', e))
        c_keywords = {'if','else','while','for','do','switch','case','default',
                      'return','break','continue','goto','sizeof','typedef',
                      'struct','union','enum','auto','register','static',
                      'extern','const','volatile','void','char','short','int',
                      'long','float','double','signed','unsigned'}
        return {i for i in ids if i not in c_keywords}

    def _is_constant_expression(self, expression: str) -> bool:
        """仅基于字面量/宏等判断（不考虑传播），保守地认定是不是常量表达式。"""
        expression = expression.strip().strip(';')
        if not expression:
            return True
        if self._contains_function_call(expression):
            return False
        if re.fullmatch(r'"[^"]*"', expression) or re.fullmatch(r"'[^']*'", expression):
            return True
        if re.fullmatch(r"'.'", expression):
            return True
        if re.fullmatch(r'-?\d+(\.\d+)?([eE][+-]?\d+)?', expression):
            return True
        if re.fullmatch(r'0[xX][0-9a-fA-F]+', expression):
            return True
        constants = {'NULL','null','nullptr','TRUE','FALSE','true','false'}
        if expression in constants or expression == '0':
            return True
        if re.fullmatch(r'[A-Z_][A-Z0-9_]*', expression):
            return True
        rest = self._strip_literals_and_ops(expression)
        if not rest:
            return True
        return False

    def _expr_is_constant_after_propagation(self, expr: str, pure_vars: Set[str]) -> bool:
        """在已有 pure_vars 的前提下，判断表达式是否为常量（可由纯常量变量组成）。"""
        expr = expr.strip().rstrip(';')
        if not expr:
            return True
        if self._contains_function_call(expr):
            return False
        rest = self._strip_literals_and_ops(expr)
        if not rest:
            return True
        ids = self._expr_identifiers(expr)
        if not ids:
            return True
        return ids.issubset(pure_vars)

    # -------------------- 常量传播核心 --------------------

    def _compute_pure_constant_vars(self) -> Set[str]:
        """迭代求解“纯常量变量”集合。"""
        pure: Set[str] = set()
        changed = True
        while changed:
            changed = False
            for var, assigns in self.assignments_by_var.items():
                if not assigns:
                    continue
                ok_all = True
                for _, rhs in assigns:
                    if not self._expr_is_constant_after_propagation(rhs, pure):
                        ok_all = False
                        break
                if ok_all and var not in pure:
                    pure.add(var)
                    changed = True
        self.pure_constant_vars = pure
        return pure

    def _arg_is_constant_after_propagation(self, arg: str) -> bool:
        if self._is_constant_expression(arg):
            return True
        return self._expr_is_constant_after_propagation(arg, self.pure_constant_vars)

    def _mark_fixed_param_calls_after_propagation(self) -> None:
        """传播后再扫描：若调用的所有实参均为常量（含纯常量变量）则标记为固定参数调用。"""
        for line_num, (func_name, args) in self.function_calls.items():
            if not args:
                self.fixed_param_calls.add(line_num)
                continue
            all_const = True
            for arg in args:
                if not self._arg_is_constant_after_propagation(arg):
                    all_const = False
                    break
            if all_const:
                # 如需保留危险函数的固定参数调用，请加：and func_name not in self.dangerous_functions
                self.fixed_param_calls.add(line_num)

    # -------------------- 污点分析 --------------------

    def find_taint_sources(self, target_function: str = 'system') -> Set[int]:
        taint_sources = set()
        for line_num, (func_name, _args) in self.function_calls.items():
            if func_name == target_function:
                taint_sources.add(line_num)
        return taint_sources

    def backward_taint_analysis(self, taint_sources: Set[int]) -> Set[int]:
        tainted_vars = set()
        required_lines = set(taint_sources)

        # 初始：收集危险函数参数中的变量
        for line_num in taint_sources:
            if line_num in self.function_calls:
                _func_name, args = self.function_calls[line_num]
                for arg in args:
                    vars_in_arg = self._extract_variables_from_expression(arg)
                    tainted_vars.update(vars_in_arg)

        queue = deque(tainted_vars)
        visited_vars = set()

        while queue:
            current_var = queue.popleft()
            if current_var in visited_vars:
                continue
            visited_vars.add(current_var)

            # 定义该变量的行（排除纯常量赋值）
            for ln in self.var_definitions[current_var]:
                if ln not in self.constant_assignments and not self._is_pure_const_assignment_line(ln):
                    required_lines.add(ln)

            # 使用该变量的行（排除固定参数调用行）
            for ln in self.var_usages[current_var]:
                if ln not in self.fixed_param_calls:
                    required_lines.add(ln)

            # 向“上游”走（谁影响了 current_var）
            for dep in self.dependency_graph.get(current_var, set()):
                if dep not in visited_vars:
                    queue.append(dep)
                    tainted_vars.add(dep)

            # 向“下游”走（current_var 影响了谁）
            for var, dependencies in self.dependency_graph.items():
                if current_var in dependencies and var not in visited_vars:
                    queue.append(var)
                    tainted_vars.add(var)

        return required_lines

    # -------------------- 代码输出与报告 --------------------

    def _is_pure_const_assignment_line(self, i: int) -> bool:
        """判断某行是否是给“纯常量变量”做常量（传播后）赋值，可删除。"""
        expr = self.rhs_by_line.get(i)
        if expr is None:
            return False
        m = re.match(r'\s*(\w+)\s*=', self.code_lines[i].strip().rstrip(';'))
        if not m:
            return False
        var = m.group(1)
        return var in self.pure_constant_vars and self._expr_is_constant_after_propagation(expr, self.pure_constant_vars)

    def _line_contains_banned_function(self, i: int) -> bool:
        """该行是否包含需删除的函数调用（仅精准匹配 printf(...)，不会误伤 sprintf 等）。"""
        line = self.code_lines[i]
        if not line.strip():
            return False
        # (?<!\w) 与 (?!\w) 确保是完整的标识符，不是前后还连着字母/数字/下划线
        # 允许中间有空白再接 '('
        pattern = r'(?<![A-Za-z0-9_])(?:' + '|'.join(re.escape(n) for n in self.banned_functions) + r')(?![A-Za-z0-9_])\s*\('
        return re.search(pattern, line) is not None

    def optimize_code(self, code: str, target_function: str = 'system') -> str:
        self.parse_c_code(code)

        taint_sources = self.find_taint_sources(target_function)
        if not taint_sources:
            return code

        required_lines = self.backward_taint_analysis(taint_sources)

        self._add_structural_lines(required_lines)

        optimized_lines: List[str] = []
        const_prop_removed = 0
        for i, line in enumerate(self.code_lines):
            if not line.strip():
                optimized_lines.append(line)
                continue

            # —— 优先：无条件删除包含 printf/xx 的行 —— #
            if self._line_contains_banned_function(i):
                # optimized_lines.append(f"// REMOVED (BANNED_FUNC): {line}")
                continue

            # 其次：删除固定参数调用（包括 return puts("...")）
            if i in required_lines:
                
                optimized_lines.append(f"{line}")
            # elif self._is_pure_const_assignment_line(i):
            #     const_prop_removed += 1
            #     optimized_lines.append(f"// REMOVED (CONST_PROP): {line}")
            # elif i in self.constant_assignments:
            #     optimized_lines.append(f"// REMOVED (CONSTANT): {line}")
            # elif i in self.fixed_param_calls:
            #     optimized_lines.append(f"// REMOVED (FIXED_PARAMS): {line}")
            # else:
            #     optimized_lines.append(f"// REMOVED (UNRELATED): {line}")

        total_lines = len([l for l in self.code_lines if l.strip()])
        kept_lines = len([i for i in required_lines if self.code_lines[i].strip()])
        constant_removed = len([i for i in self.constant_assignments if self.code_lines[i].strip()])
        fixed_param_removed = len([i for i in self.fixed_param_calls if self.code_lines[i].strip()])
        other_removed = total_lines - kept_lines - constant_removed - fixed_param_removed - const_prop_removed
        reduction_rate = (total_lines - kept_lines) / total_lines * 100 if total_lines else 0.0

        optimized_lines.append("")
        optimized_lines.append("// ===== 优化统计 =====")
        optimized_lines.append(f"// 原始代码行数: {total_lines}")
        optimized_lines.append(f"// 保留代码行数: {kept_lines}")
        optimized_lines.append(f"// 删除常量赋值: {constant_removed} 行")
        optimized_lines.append(f"// 删除传播后纯常量赋值: {const_prop_removed} 行")
        optimized_lines.append(f"// 删除固定参数函数调用: {fixed_param_removed} 行")
        optimized_lines.append(f"// 删除其他无关代码: {max(other_removed, 0)} 行")
        optimized_lines.append(f"// 总代码减少率: {reduction_rate:.1f}%")

        return '\n'.join(optimized_lines)

    def _add_structural_lines(self, required_lines: Set[int]) -> None:
        """添加结构性代码，但跳过含固定参数调用的 return 行"""
        additional_lines = set()
        for i, line in enumerate(self.code_lines):
            s = line.strip()
            if not s:
                continue
            # 函数签名/括号/预处理
            if (s.startswith('int ') and '(' in s and ')' in s) or \
               s in ['{', '}'] or \
               s.startswith('#include') or \
               s.startswith('#define'):
                additional_lines.add(i)
                continue
            # return 行：如果这一行也被标记为 fixed_param_calls，就不当结构性行加入
            if s.startswith('return'):
                if i not in self.fixed_param_calls and not self._line_contains_banned_function(i):
                    additional_lines.add(i)
                continue
        required_lines.update(additional_lines)

    def generate_analysis_report(self, code: str, target_function: str = 'system') -> str:
        self.parse_c_code(code)

        report: List[str] = []
        report.append("=" * 60)
        report.append(f"污点分析报告 - 目标函数: {target_function}")
        report.append("=" * 60)

        taint_sources = self.find_taint_sources(target_function)
        if not taint_sources:
            report.append(f"未找到目标函数 '{target_function}' 的调用")
            return '\n'.join(report)

        required_lines = self.backward_taint_analysis(taint_sources)

        report.append(f"\n危险函数调用位置:")
        for line_num in sorted(taint_sources):
            if line_num in self.function_calls:
                func_name, args = self.function_calls[line_num]
                args_view = ', '.join(args)
                report.append(f"  第{line_num + 1}行: {func_name}({args_view})")

        report.append(f"\n相关代码行 (共{len(required_lines)}行):")
        for line_num in sorted(required_lines):
            if line_num < len(self.code_lines):
                report.append(f"  第{line_num + 1}行: {self.code_lines[line_num].strip()}")

        report.append(f"\n变量依赖关系:")
        for var, deps in self.dependency_graph.items():
            if deps:
                report.append(f"  {var} <- {', '.join(sorted(deps))}")

        report.append(f"\n纯常量变量 (传播后): {', '.join(sorted(self.pure_constant_vars)) if self.pure_constant_vars else '(无)'}")
        report.append(f"\n固定参数调用行 (传播后识别): {', '.join(str(i+1) for i in sorted(self.fixed_param_calls)) if self.fixed_param_calls else '(无)'}")
        report.append(f"字面量常量赋值行: {', '.join(str(i+1) for i in sorted(self.constant_assignments)) if self.constant_assignments else '(无)'}")

        return '\n'.join(report)

    # -------------------- 变量抽取 --------------------

    def _extract_variables_from_expression(self, expression: str) -> Set[str]:
        expr = expression
        expr = re.sub(r'"[^"]*"', '', expr)
        expr = re.sub(r"'[^']*'", '', expr)
        expr = re.sub(r'\b0[xX][0-9a-fA-F]+\b', '', expr)
        expr = re.sub(r'\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b', '', expr)
        while True:
            old_expr = expr
            expr = re.sub(r'\b\w+\s*\([^()]*\)', '', expr)
            if expr == old_expr:
                break
        variables = set()
        identifiers = re.findall(r'\b[a-zA-Z_]\w*\b', expr)
        c_keywords = {
            'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default',
            'return', 'break', 'continue', 'goto', 'sizeof', 'typedef',
            'struct', 'union', 'enum', 'auto', 'register', 'static',
            'extern', 'const', 'volatile', 'void', 'char', 'short',
            'int', 'long', 'float', 'double', 'signed', 'unsigned'
        }
        for ident in identifiers:
            if ident not in c_keywords:
                variables.add(ident)
        return variables


# -------------------- 示例主函数 --------------------

def main():
    sample_code = r'''int __fastcall formBSSetSitesurvey(int a1)
{
  const char *Var; // $s2
  const char *v3; // $s4
  int v4; // $s2
  const char *v5; // $s7
  const char *v6; // $s3
  const char *v7; // $a0
  const char *v8; // $s3
  const char *v9; // $s6
  const char *v10; // $v0
  const char *v11; // $v0
  int v12; // $a0
  const char *v13; // $a1
  int v14; // $v0
  const char *v15; // $v0
  const char *v16; // $v0
  const char *v17; // $v0
  const char *v18; // $a0
  const char *v19; // $v0
  int v20; // $a0
  const char *v21; // $a1
  const char *v22; // $a0
  const char *v23; // $a1
  int v24; // $a0
  const char *v25; // $a1
  int v26; // $a2
  int v27; // $s6
  const char *v28; // $s4
  const char *v29; // $s3
  const char *v30; // $s2
  const char *v31; // $a0
  const char *v32; // $s5
  const char *v33; // $fp
  const char *v34; // $s7
  const char *v35; // $v0
  const char *v36; // $v0
  char *v37; // $a0
  int v38; // $v0
  int v39; // $a2
  const char *v40; // $a1
  int v41; // $v0
  int v42; // $v0
  int v43; // $v0
  int v44; // $a2
  const char *v45; // $a1
  int v46; // $v0
  int v47; // $v0
  const char *v48; // $a0
  int v49; // $v0
  int v50; // $a2
  const char *v51; // $a1
  int v52; // $v0
  int v53; // $v0
  const char *v54; // $v0
  int v55; // $v0
  int v56; // $a0
  const char *v57; // $a1
  const char *v58; // $s5
  const char *v59; // $s2
  const char *v60; // $s4
  const char *v61; // $s1
  const char *v62; // $a0
  int v63; // $v0
  bool v64; // dc
  int result; // $v0
  int v66; // $v0
  const char *v67; // $v0
  int v68; // $v0
  const char *v69; // $v0
  int v70; // $v0
  int v71; // $v0
  int v72; // $s4
  int v73; // $s2
  const char *v74; // $s5
  const char *v75; // $s3
  const char *v76; // $s7
  const char *v77; // $s6
  const char *v78; // $v0
  const char *v79; // $v0
  const char *v80; // $fp
  const char *v81; // $v0
  const char *v82; // $a0
  const char *v83; // $v0
  const char *v84; // $v0
  int v85; // $a0
  int *v86; // $a1
  int v87; // $v0
  int v88; // $v0
  int v89; // $v0
  size_t v90; // $v0
  int v91; // $a0
  int *v92; // $a1
  int v93; // $a0
  int v94; // $a0
  int *v95; // $a1
  int v96; // $v0
  int v97; // $v0
  int v98; // $v0
  size_t v99; // $v0
  int v100; // $a0
  int *v101; // $a1
  int v102; // $a0
  int *v103; // $a1
  int v104; // $v0
  int v105; // $v0
  int v106; // $v0
  int v107; // $a0
  int *v108; // $a1
  int v109; // $v0
  int v110; // $v0
  int v111; // $v0
  size_t v112; // $v0
  int v113; // $a0
  int *v114; // $a1
  size_t v115; // $v0
  int v116; // $a0
  int *v117; // $a1
  int v118; // [sp+38h] [-620h] BYREF
  int v119; // [sp+3Ch] [-61Ch] BYREF
  int v120; // [sp+40h] [-618h] BYREF
  int v121; // [sp+44h] [-614h] BYREF
  int v122; // [sp+48h] [-610h] BYREF
  int v123; // [sp+4Ch] [-60Ch] BYREF
  int v124; // [sp+50h] [-608h] BYREF
  int v125; // [sp+54h] [-604h] BYREF
  int v126; // [sp+58h] [-600h] BYREF
  int v127; // [sp+5Ch] [-5FCh] BYREF
  int v128; // [sp+60h] [-5F8h] BYREF
  int v129; // [sp+64h] [-5F4h] BYREF
  int v130; // [sp+68h] [-5F0h] BYREF
  int v131; // [sp+6Ch] [-5ECh] BYREF
  int v132; // [sp+70h] [-5E8h] BYREF
  int v133; // [sp+74h] [-5E4h] BYREF
  int v134; // [sp+78h] [-5E0h] BYREF
  int v135; // [sp+7Ch] [-5DCh] BYREF
  char v136[20]; // [sp+80h] [-5D8h] BYREF
  char v137[20]; // [sp+94h] [-5C4h] BYREF
  char v138[100]; // [sp+A8h] [-5B0h] BYREF
  char v139[100]; // [sp+10Ch] [-54Ch] BYREF
  struct in_addr v140[25]; // [sp+170h] [-4E8h] BYREF
  char v141[100]; // [sp+1D4h] [-484h] BYREF
  struct in_addr v142[25]; // [sp+238h] [-420h] BYREF
  struct in_addr v143[25]; // [sp+29Ch] [-3BCh] BYREF
  struct in_addr v144[25]; // [sp+300h] [-358h] BYREF
  struct in_addr v145[25]; // [sp+364h] [-2F4h] BYREF
  struct in_addr v146[25]; // [sp+3C8h] [-290h] BYREF
  char v147[100]; // [sp+42Ch] [-22Ch] BYREF
  char v148[200]; // [sp+490h] [-1C8h] BYREF
  char v149[200]; // [sp+558h] [-100h] BYREF
  const char *v150; // [sp+620h] [-38h]
  char *v151; // [sp+624h] [-34h]
  void *s; // [sp+628h] [-30h]
  char *v153; // [sp+62Ch] [-2Ch]
  void *v154; // [sp+630h] [-28h]
  char *v155; // [sp+634h] [-24h]
  char *v156; // [sp+638h] [-20h]
  int v157; // [sp+63Ch] [-1Ch]
  int v158; // [sp+640h] [-18h]
  const char *v159; // [sp+644h] [-14h]
  const char *v160; // [sp+648h] [-10h]
  const char *v161; // [sp+64Ch] [-Ch]
  const char *v162; // [sp+650h] [-8h]
  const char *v163; // [sp+654h] [-4h]

  v120 = 0;
  v121 = 0;
  Var = (const char *)websGetVar(a1, "action", "");
  if ( strcmp(Var, "done") )
  {
    if ( !strcmp(Var, "SetPassWord") )
    {
      v27 = websGetVar(a1, "wl_ssid", "");
      v28 = (const char *)websGetVar(a1, "wl_ssidforfile", "");
      v158 = websGetVar(a1, "wl_seckey", "");
      v157 = websGetVar(a1, "wl_seckeyforfile", "");
      v29 = (const char *)websGetVar(a1, "formHiddenSSID", "");
      v156 = (char *)websGetVar(a1, "wl_rssi", "");
      v30 = (const char *)websGetVar(a1, "hidden_sectype", "");
      v155 = (char *)websGetVar(a1, "fromFlag", "");
      if ( strcmp(v29, "formHiddenSSIDpage") )
      {
        v34 = (const char *)websGetVar(a1, "wl_security", "");
        v35 = (const char *)websGetVar(a1, "wl_channel", "");
        v120 = strtol(v35, 0, 10);
        v33 = (const char *)websGetVar(a1, "wl_band", "");
        v36 = (const char *)websGetVar(a1, "wl_bandwidth", "");
        v118 = strtol(v36, 0, 10);
        v150 = (const char *)websGetVar(a1, "wl_bandtype", "");
        v32 = (const char *)websGetVar(a1, "wl_bssid", "");
      }
      else
      {
        puts("===>hidden handler from SetPassWord Action");
        if ( wlgetHiddenSSIDinfo(v27) )
        {
          strcpy(v136, "2");
          v31 = "ifconfig wlan1-vxd 0.0.0.0";
        }
        else
        {
          if ( !wlgetHiddenSSIDinfo5g(v27, 4653056) )
          {
LABEL_360:
            v56 = a1;
            v57 = "location_page";
            goto LABEL_361;
          }
          strcpy(v136, "5");
          v31 = "ifconfig wlan0-vxd 0.0.0.0";
        }
        system(v31);
        printf("===> strSecTypehidde=%s ,outSecType=%s \n", v30, outSecType);
        if ( strcmp(v30, outSecType) && (strcmp("020", outSecType) || !strcmp("100", v30)) )
        {
          puts("===> SecurityType Compare Failed to surveyfailed page ");
          goto LABEL_70;
        }
        v32 = "00:00:00:00:00:00";
        v33 = v136;
        v118 = outBandwidth;
        v120 = outChan;
        switchChan = outChan;
        v34 = outSecType;
        v150 = outBandType;
      }
      v151 = (char *)v140;
      memset(v139, 0, sizeof(v139));
      s = v141;
      v153 = (char *)v142;
      v154 = v143;
      sub_447590(v139, v33, off_48EF20[0]);
      memset(v151, 0, 0x64u);
      v37 = v151;
      v151 = (char *)v146;
      sub_447590(v37, v28, off_48EF24);
      memset(s, 0, 0x64u);
      sub_447590(s, v34, off_48EF20[0]);
      memset(v153, 0, 0x64u);
      sub_447590(v153, v157, off_48EF24);
      memset(v154, 0, 0x64u);
      sub_447590(v154, v27, off_48EF24);
      memset(v144, 0, sizeof(v144));
      sub_447590(v144, v158, off_48EF24);
      memset(v145, 0, sizeof(v145));
      sub_447590(v145, v150, off_48EF20[0]);
      memset(v151, 0, 0x64u);
      sub_447590(v151, v156, off_48EF20[0]);
      if ( !strcmp(v33, "2") )
      {
        if ( !strcmp(v155, "true") )
        {
          puts("---> iDevice Detected!!");
          v38 = strcmp(v34, "100");
          v39 = v27;
          if ( v38 )
          {
            v41 = strcmp(v34, "001");
            v39 = v27;
            if ( v41 )
            {
              v42 = strcmp(v34, "002");
              v39 = v27;
              if ( v42 )
              {
                if ( strcmp(v34, "010") )
                  sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 5 \"%s\" %d %s &", v27, v120, v144, v118, v145);
                else
                  sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 4 \"%s\" %d %s &", v27, v120, v144, v118, v145);
                goto LABEL_85;
              }
              v40 = "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 3 \"%s\" %d %s &";
            }
            else
            {
              v40 = "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 2 \"%s\" %d %s &";
            }
          }
          else
          {
            v40 = "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 1 \"%s\" %d %s &";
          }
          sprintf(v148, v40, v39, v120, v144, v118, v145);
LABEL_85:
          v159 = v148;
          system(v148);
          printf("---> Do test 2.4g for iDev= %s\n", v159);
LABEL_97:
          v48 = "cat /proc/wlan1-vxd/sta_info | grep active | cut -d ' ' -f 7 > /var/sta_info";
LABEL_110:
          system(v48);
          goto LABEL_111;
        }
        v43 = strcmp(v34, "100");
        v44 = v27;
        if ( v43 )
        {
          v46 = strcmp(v34, "001");
          v44 = v27;
          if ( v46 )
          {
            v47 = strcmp(v34, "002");
            v44 = v27;
            if ( v47 )
            {
              if ( strcmp(v34, "010") )
                sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 5 \"%s\" %d %s &", v27, v120, v144, v118, v145);
              else
                sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 4 \"%s\" %d %s &", v27, v120, v144, v118, v145);
              goto LABEL_96;
            }
            v45 = "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 3 \"%s\" %d %s &";
          }
          else
          {
            v45 = "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 2 \"%s\" %d %s &";
          }
        }
        else
        {
          v45 = "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 1 \"%s\" %d %s &";
        }
        sprintf(v148, v45, v44, v120, v144, v118, v145);
LABEL_96:
        v159 = v148;
        system(v148);
        printf("---> 2.4g command=%s\n", v159);
        goto LABEL_97;
      }
      if ( strcmp(v33, "5") )
      {
LABEL_111:
        memset(v147, 0, sizeof(v147));
        sub_447590(v147, v32, off_48EF20[0]);
        sprintf(
          v149,
          "echo %s \"%s\" %s %d %d \"%s\" %s 0 %s %s > /var/SiteSurveyResult.var",
          v139,
          v28,
          v141,
          v120,
          v118,
          (const char *)v142,
          (const char *)v145,
          (const char *)v146,
          v147);
        printf("---> @SetPassWord %s Create SiteSurveyResult\n", v149);
        system(v149);
        v54 = (const char *)websGetVar(a1, "submit-url-ok", "");
        sprintf(v138, "/%s", v54);
        v20 = a1;
        v21 = v138;
        return websRedirect(v20, v21);
      }
      v49 = strcmp(v34, "100");
      v50 = v27;
      if ( v49 )
      {
        v52 = strcmp(v34, "001");
        v50 = v27;
        if ( v52 )
        {
          v53 = strcmp(v34, "002");
          v50 = v27;
          if ( v53 )
          {
            if ( strcmp(v34, "010") )
              sprintf(v148, "/bin/wlan5bandt.sh wlan0-vxd \"%s\" %d 5 \"%s\" %d %s &", v27, v120, v144, v118, v145);
            else
              sprintf(v148, "/bin/wlan5bandt.sh wlan0-vxd \"%s\" %d 4 \"%s\" %d %s &", v27, v120, v144, v118, v145);
            goto LABEL_109;
          }
          v51 = "/bin/wlan5bandt.sh wlan0-vxd \"%s\" %d 3 \"%s\" %d %s &";
        }
        else
        {
          v51 = "/bin/wlan5bandt.sh wlan0-vxd \"%s\" %d 2 \"%s\" %d %s &";
        }
      }
      else
      {
        v51 = "/bin/wlan5bandt.sh wlan0-vxd \"%s\" %d 1 \"%s\" %d %s &";
      }
      sprintf(v148, v51, v50, v120, v144, v118, v145);
LABEL_109:
      v159 = v148;
      system(v148);
      printf("---> 5g command=%s\n", v159);
      v48 = "cat /proc/wlan0-vxd/sta_info | grep active | cut -d ' ' -f 7 > /var/sta_info";
      goto LABEL_110;
    }
    v55 = strcmp(Var, "finishing");
    v56 = a1;
    if ( !v55 )
    {
      v57 = "submit-url";
LABEL_361:
      v26 = websGetVar(v56, v57, "");
      goto LABEL_362;
    }
    if ( !strcmp(Var, "SetStaticIP") )
    {
      system("killall udhcpc");
      v58 = (const char *)websGetVar(a1, "currentband", "");
      v59 = (const char *)websGetVar(a1, "wan_ipaddr", "");
      v60 = (const char *)websGetVar(a1, "wan_netmask", "");
      v61 = (const char *)websGetVar(a1, "wan_gateway", "");
      if ( strcmp(v58, "2") )
      {
        sprintf(v149, "ifconfig wlan0-vxd %s", v59);
        system(v149);
        v62 = "echo 5 > /tmp/static_ip_band";
      }
      else
      {
        sprintf(v149, "ifconfig wlan1-vxd %s", v59);
        system(v149);
        v62 = "echo 2 > /tmp/static_ip_band";
      }
      system(v62);
      sprintf(v148, "echo %s %s %s > /var/tmp_static_ip", v59, v60, v61);
      system(v148);
      v12 = a1;
      v13 = "submit-url-ok";
      goto LABEL_119;
    }
    v64 = strcmp(Var, "reboot") != 0;
    result = 6;
    if ( v64 )
      return result;
    v122 = 6;
    v123 = 0;
    v124 = 0;
    v125 = 0;
    v126 = 0;
    v127 = 0;
    v128 = 0;
    v66 = websGetVar(a1, "repeaterSSID", "");
    v154 = (void *)CharSpaceAdd(v66);
    v67 = (const char *)websGetVar(a1, "channel", "");
    v120 = strtol(v67, 0, 10);
    v68 = websGetVar(a1, "repeaterSSID5g", "");
    v157 = CharSpaceAdd(v68);
    v69 = (const char *)websGetVar(a1, "channel5g", "");
    v121 = strtol(v69, 0, 10);
    v70 = websGetVar(a1, "self_ssid", "");
    v156 = (char *)CharSpaceAdd(v70);
    v71 = websGetVar(a1, "self_ssid5g", "");
    v155 = (char *)CharSpaceAdd(v71);
    v72 = websGetVar(a1, "rptpassword", "");
    v73 = websGetVar(a1, "rptpassword5g", "");
    v74 = (const char *)websGetVar(a1, "rptpasswordType", "");
    v75 = (const char *)websGetVar(a1, "rptpasswordType5g", "");
    v76 = (const char *)websGetVar(a1, "self_password", "");
    v77 = (const char *)websGetVar(a1, "self_password5g", "");
    s = (void *)websGetVar(a1, "self_passwordType", "");
    v151 = (char *)websGetVar(a1, "self_passwordType5g", "");
    v78 = (const char *)websGetVar(a1, "bandtype", "");
    v130 = strtol(v78, 0, 10);
    v79 = (const char *)websGetVar(a1, "bandtype5g", "");
    v131 = strtol(v79, 0, 10);
    v150 = (const char *)websGetVar(a1, "root_ap_bssid", "");
    v80 = (const char *)websGetVar(a1, "root_ap_bssid5g", "");
    v153 = (char *)websGetVar(a1, "BandConnetInfo", "");
    v163 = (const char *)websGetVar(a1, "ipaddr", "");
    v159 = (const char *)websGetVar(a1, "ipaddr5g", "");
    v160 = (const char *)websGetVar(a1, "netmask", "");
    v161 = (const char *)websGetVar(a1, "gateway", "");
    v162 = (const char *)websGetVar(a1, "gateway5g", "");
    v81 = (const char *)websGetVar(a1, "gnetmask", "");
    v82 = v163;
    v163 = v81;
    inet_aton(v82, v140);
    inet_aton(v159, v142);
    inet_aton(v160, v143);
    inet_aton(v163, v144);
    inet_aton(v161, v145);
    inet_aton(v162, v146);
    v83 = (const char *)websGetVar(a1, "chan_bandwidth", "");
    v118 = strtol(v83, 0, 10);
    v84 = (const char *)websGetVar(a1, "chan_bandwidth5g", "");
    v119 = strtol(v84, 0, 10);
    if ( !strcmp(v153, "1") )
    {
      if ( !apmib_set(1, v156) )
        return puts("Setting Flash error");
      if ( !apmib_set(399, &v122) )
        return puts("Setting Flash error");
      if ( !apmib_set(534, v154) )
        return puts("Setting Flash error");
      if ( !apmib_set(2, &v120) )
        return puts("Setting Flash error");
      if ( !apmib_set(28, &v118) )
        return puts("Setting Flash error");
      v132 = 1;
      if ( !apmib_set(513, &v132) )
        return puts("Setting Flash error");
      v133 = 0;
      if ( !apmib_set(90, &v133) )
        return puts("Setting Flash error");
      if ( strcmp((const char *)s, "0") )
      {
        v132 = 1;
        if ( !apmib_set(518, &v132) || !apmib_set(519, &v132) || !apmib_set(95, &v132) || !apmib_set(96, &v132) )
          return puts("Setting Flash error");
      }
      if ( !strcmp(v74, "100") )
      {
        if ( !apmib_set(546, v72) )
          return puts("Setting Flash error");
        v85 = 537;
        v86 = &v125;
        v125 = 1;
        goto LABEL_155;
      }
      if ( !strcmp(v74, "001") )
      {
        if ( !apmib_set(550, v72) )
          return puts("Setting Flash error");
        v125 = 2;
        v87 = apmib_set(537, &v125);
        v85 = 544;
        if ( !v87 )
          return puts("Setting Flash error");
        v123 = 0;
        goto LABEL_154;
      }
      if ( strcmp(v74, "002") )
      {
        if ( !strcmp(v74, "010") )
        {
          if ( !apmib_set(550, v72) )
            return puts("Setting Flash error");
          v125 = 2;
          v89 = apmib_set(537, &v125);
          v85 = 544;
          if ( !v89 )
            return puts("Setting Flash error");
          v123 = 2;
          goto LABEL_154;
        }
        if ( strcmp(v74, "020") )
          goto LABEL_156;
        if ( !apmib_set(550, v72) )
          return puts("Setting Flash error");
        v125 = 2;
        if ( !apmib_set(537, &v125) )
          return puts("Setting Flash error");
        v88 = 3;
      }
      else
      {
        if ( !apmib_set(550, v72) )
          return puts("Setting Flash error");
        v125 = 2;
        if ( !apmib_set(537, &v125) )
          return puts("Setting Flash error");
        v88 = 1;
      }
      v123 = v88;
      v85 = 544;
LABEL_154:
      v86 = &v123;
LABEL_155:
      if ( !apmib_set(v85, v86) )
        return puts("Setting Flash error");
LABEL_156:
      if ( strcmp((const char *)s, "1") )
      {
        if ( strcmp((const char *)s, "4") )
          goto LABEL_172;
        if ( !apmib_set(135, v76) )
          return puts("Setting Flash error");
        v125 = 6;
        if ( !apmib_set(130, &v125) )
          return puts("Setting Flash error");
        v123 = 3;
        if ( !apmib_set(134, &v123) )
          return puts("Setting Flash error");
        v135 = 3;
        if ( !apmib_set(504, &v135) )
          return puts("Setting Flash error");
        v92 = &v134;
        v134 = 2;
      }
      else
      {
        v125 = 1;
        v90 = strlen(v76);
        sub_447990(v76, v147, v90);
        if ( !apmib_set(130, &v125) )
          return puts("Setting Flash error");
        if ( strlen(v76) == 10 )
        {
          v127 = 1;
          if ( !apmib_set(3, &v127) )
            return puts("Setting Flash error");
          v91 = 4;
        }
        else
        {
          v127 = 2;
          if ( !apmib_set(3, &v127) )
            return puts("Setting Flash error");
          v91 = 8;
        }
        if ( !apmib_set(v91, v147) )
          return puts("Setting Flash error");
        v92 = &v135;
        v135 = 1;
      }
      if ( !apmib_set(406, v92) )
        return puts("Setting Flash error");
LABEL_172:
      if ( !apmib_set(501, &v130)
        || fopen("/var/static_ip2", "r") && (!apmib_set(314, v140) || !apmib_set(315, v143) || !apmib_set(317, v145)) )
      {
        return puts("Setting Flash error");
      }
      if ( *v150 )
      {
        if ( strlen(v150) != 12 || !sub_447990(v150, v138, 12) )
          return puts("Setting Flash error");
        v93 = 103;
LABEL_241:
        if ( !apmib_set(v93, v138) )
          return puts("Setting Flash error");
        goto LABEL_242;
      }
      goto LABEL_242;
    }
    if ( !strcmp(v153, "2") )
    {
      if ( !apmib_set(39, v155) )
        return puts("Setting Flash error");
      if ( !apmib_set(84, &v122) )
        return puts("Setting Flash error");
      if ( !apmib_set(558, v157) )
        return puts("Setting Flash error");
      if ( !apmib_set(40, &v121) )
        return puts("Setting Flash error");
      if ( !apmib_set(34, &v119) )
        return puts("Setting Flash error");
      v134 = 0;
      if ( !apmib_set(513, &v134) )
        return puts("Setting Flash error");
      v135 = 1;
      if ( !apmib_set(90, &v135) )
        return puts("Setting Flash error");
      if ( strcmp(v151, "0") )
      {
        v134 = 1;
        if ( !apmib_set(518, &v134) || !apmib_set(519, &v134) || !apmib_set(95, &v134) || !apmib_set(96, &v134) )
          return puts("Setting Flash error");
      }
      if ( !strcmp(v75, "100") )
      {
        if ( !apmib_set(570, v73) )
          return puts("Setting Flash error");
        v94 = 561;
        v95 = &v126;
        v126 = 1;
        goto LABEL_215;
      }
      if ( !strcmp(v75, "001") )
      {
        if ( !apmib_set(574, v73) )
          return puts("Setting Flash error");
        v126 = 2;
        v96 = apmib_set(561, &v126);
        v94 = 568;
        if ( !v96 )
          return puts("Setting Flash error");
        v124 = 0;
        goto LABEL_214;
      }
      if ( strcmp(v75, "002") )
      {
        if ( !strcmp(v75, "010") )
        {
          if ( !apmib_set(574, v73) )
            return puts("Setting Flash error");
          v126 = 2;
          v98 = apmib_set(561, &v126);
          v94 = 568;
          if ( !v98 )
            return puts("Setting Flash error");
          v124 = 2;
          goto LABEL_214;
        }
        if ( strcmp(v75, "020") )
          goto LABEL_216;
        if ( !apmib_set(574, v73) )
          return puts("Setting Flash error");
        v126 = 2;
        if ( !apmib_set(561, &v126) )
          return puts("Setting Flash error");
        v97 = 3;
      }
      else
      {
        if ( !apmib_set(574, v73) )
          return puts("Setting Flash error");
        v126 = 2;
        if ( !apmib_set(561, &v126) )
          return puts("Setting Flash error");
        v97 = 1;
      }
      v124 = v97;
      v94 = 568;
LABEL_214:
      v95 = &v124;
LABEL_215:
      if ( !apmib_set(v94, v95) )
        return puts("Setting Flash error");
LABEL_216:
      if ( strcmp(v151, "1") )
      {
        if ( strcmp(v151, "4") )
          goto LABEL_232;
        if ( !apmib_set(117, v77) )
          return puts("Setting Flash error");
        v126 = 6;
        if ( !apmib_set(112, &v126) )
          return puts("Setting Flash error");
        v124 = 3;
        if ( !apmib_set(116, &v124) )
          return puts("Setting Flash error");
        v133 = 3;
        if ( !apmib_set(71, &v133) )
          return puts("Setting Flash error");
        v101 = &v132;
        v132 = 2;
      }
      else
      {
        v99 = strlen(v77);
        sub_447990(v77, v147, v99);
        v126 = 1;
        if ( !apmib_set(112, &v126) )
          return puts("Setting Flash error");
        if ( strlen(v77) == 10 )
        {
          v128 = 1;
          if ( !apmib_set(41, &v128) )
            return puts("Setting Flash error");
          v100 = 42;
        }
        else
        {
          v128 = 2;
          if ( !apmib_set(41, &v128) )
            return puts("Setting Flash error");
          v100 = 46;
        }
        if ( !apmib_set(v100, v147) )
          return puts("Setting Flash error");
        v101 = &v133;
        v133 = 1;
      }
      if ( !apmib_set(85, v101) )
        return puts("Setting Flash error");
LABEL_232:
      if ( !apmib_set(68, &v131)
        || fopen("/var/static_ip5", "r") && (!apmib_set(366, v142) || !apmib_set(367, v144) || !apmib_set(368, v146)) )
      {
        return puts("Setting Flash error");
      }
      if ( *v80 )
      {
        if ( strlen(v80) != 12 || !sub_447990(v80, v138, 12) )
          return puts("Setting Flash error");
        v93 = 104;
        goto LABEL_241;
      }
LABEL_242:
      v129 = 0;
LABEL_357:
      if ( apmib_set(377, &v129) )
        goto LABEL_358;
      return puts("Setting Flash error");
    }
    if ( strcmp(v153, "3") )
    {
LABEL_358:
      v159 = (const char *)websGetVar(a1, "submit-url", "");
      apmib_update(4);
      sprintf(v138, "/%s", v159);
      websRedirect(a1, v138);
      return system("reboot.sh 4 &");
    }
    if ( !apmib_set(1, v156) )
      return puts("Setting Flash error");
    if ( !apmib_set(399, &v122) )
      return puts("Setting Flash error");
    if ( !apmib_set(39, v155) )
      return puts("Setting Flash error");
    if ( !apmib_set(84, &v122) )
      return puts("Setting Flash error");
    if ( !apmib_set(534, v154) )
      return puts("Setting Flash error");
    if ( !apmib_set(2, &v120) )
      return puts("Setting Flash error");
    if ( !apmib_set(558, v157) )
      return puts("Setting Flash error");
    if ( !apmib_set(40, &v121) )
      return puts("Setting Flash error");
    if ( !apmib_set(28, &v118) )
      return puts("Setting Flash error");
    if ( !apmib_set(34, &v119) )
      return puts("Setting Flash error");
    v132 = 1;
    if ( !apmib_set(513, &v132) )
      return puts("Setting Flash error");
    v133 = 0;
    if ( !apmib_set(90, &v133) )
      return puts("Setting Flash error");
    if ( strcmp((const char *)s, "0") )
    {
      v132 = 1;
      if ( !apmib_set(518, &v132) || !apmib_set(519, &v132) )
        return puts("Setting Flash error");
    }
    if ( strcmp(v151, "0") )
    {
      v132 = 1;
      if ( !apmib_set(95, &v132) || !apmib_set(96, &v132) )
        return puts("Setting Flash error");
    }
    if ( !strcmp(v74, "100") )
    {
      if ( !apmib_set(546, v72) )
        return puts("Setting Flash error");
      v102 = 537;
      v103 = &v125;
      v125 = 1;
      goto LABEL_283;
    }
    if ( !strcmp(v74, "001") )
    {
      if ( !apmib_set(550, v72) )
        return puts("Setting Flash error");
      v125 = 2;
      v104 = apmib_set(537, &v125);
      v102 = 544;
      if ( !v104 )
        return puts("Setting Flash error");
      v123 = 0;
      goto LABEL_282;
    }
    if ( strcmp(v74, "002") )
    {
      if ( !strcmp(v74, "010") )
      {
        if ( !apmib_set(550, v72) )
          return puts("Setting Flash error");
        v125 = 2;
        v106 = apmib_set(537, &v125);
        v102 = 544;
        if ( !v106 )
          return puts("Setting Flash error");
        v123 = 2;
        goto LABEL_282;
      }
      if ( strcmp(v74, "020") )
        goto LABEL_284;
      if ( !apmib_set(550, v72) )
        return puts("Setting Flash error");
      v125 = 2;
      if ( !apmib_set(537, &v125) )
        return puts("Setting Flash error");
      v105 = 3;
    }
    else
    {
      if ( !apmib_set(550, v72) )
        return puts("Setting Flash error");
      v125 = 2;
      if ( !apmib_set(537, &v125) )
        return puts("Setting Flash error");
      v105 = 1;
    }
    v123 = v105;
    v102 = 544;
LABEL_282:
    v103 = &v123;
LABEL_283:
    if ( !apmib_set(v102, v103) )
      return puts("Setting Flash error");
LABEL_284:
    if ( !strcmp(v75, "100") )
    {
      if ( !apmib_set(570, v73) )
        return puts("Setting Flash error");
      v107 = 561;
      v108 = &v126;
      v126 = 1;
      goto LABEL_305;
    }
    if ( !strcmp(v75, "001") )
    {
      if ( !apmib_set(574, v73) )
        return puts("Setting Flash error");
      v126 = 2;
      v109 = apmib_set(561, &v126);
      v107 = 568;
      if ( !v109 )
        return puts("Setting Flash error");
      v124 = 0;
      goto LABEL_304;
    }
    if ( strcmp(v75, "002") )
    {
      if ( !strcmp(v75, "010") )
      {
        if ( !apmib_set(574, v73) )
          return puts("Setting Flash error");
        v126 = 2;
        v111 = apmib_set(561, &v126);
        v107 = 568;
        if ( !v111 )
          return puts("Setting Flash error");
        v124 = 2;
        goto LABEL_304;
      }
      if ( strcmp(v75, "020") )
        goto LABEL_306;
      if ( !apmib_set(574, v73) )
        return puts("Setting Flash error");
      v126 = 2;
      if ( !apmib_set(561, &v126) )
        return puts("Setting Flash error");
      v110 = 3;
    }
    else
    {
      if ( !apmib_set(574, v73) )
        return puts("Setting Flash error");
      v126 = 2;
      if ( !apmib_set(561, &v126) )
        return puts("Setting Flash error");
      v110 = 1;
    }
    v124 = v110;
    v107 = 568;
LABEL_304:
    v108 = &v124;
LABEL_305:
    if ( !apmib_set(v107, v108) )
      return puts("Setting Flash error");
LABEL_306:
    if ( strcmp((const char *)s, "1") )
    {
      if ( strcmp((const char *)s, "4") )
        goto LABEL_322;
      if ( !apmib_set(135, v76) )
        return puts("Setting Flash error");
      v125 = 6;
      if ( !apmib_set(130, &v125) )
        return puts("Setting Flash error");
      v123 = 3;
      if ( !apmib_set(134, &v123) )
        return puts("Setting Flash error");
      v135 = 3;
      if ( !apmib_set(504, &v135) )
        return puts("Setting Flash error");
      v114 = &v134;
      v134 = 2;
    }
    else
    {
      v112 = strlen(v76);
      sub_447990(v76, v147, v112);
      v125 = 1;
      if ( !apmib_set(130, &v125) )
        return puts("Setting Flash error");
      if ( strlen(v76) == 10 )
      {
        v127 = 1;
        if ( !apmib_set(3, &v127) )
          return puts("Setting Flash error");
        v113 = 4;
      }
      else
      {
        v127 = 2;
        if ( !apmib_set(3, &v127) )
          return puts("Setting Flash error");
        v113 = 8;
      }
      if ( !apmib_set(v113, v147) )
        return puts("Setting Flash error");
      v114 = &v135;
      v135 = 1;
    }
    if ( !apmib_set(406, v114) )
      return puts("Setting Flash error");
LABEL_322:
    if ( strcmp(v151, "1") )
    {
      if ( strcmp(v151, "4") )
      {
LABEL_338:
        if ( !apmib_set(501, &v130)
          || !apmib_set(68, &v131)
          || *v150 && (strlen(v150) != 12 || !sub_447990(v150, v138, 12) || !apmib_set(103, v138))
          || *v80 && (strlen(v80) != 12 || !sub_447990(v80, v138, 12) || !apmib_set(104, v138))
          || fopen("/var/static_ip2", "r") && (!apmib_set(314, v140) || !apmib_set(315, v143) || !apmib_set(317, v145))
          || fopen("/var/static_ip5", "r") && (!apmib_set(366, v142) || !apmib_set(367, v144) || !apmib_set(368, v146)) )
        {
          return puts("Setting Flash error");
        }
        v129 = 1;
        goto LABEL_357;
      }
      if ( !apmib_set(117, v77) )
        return puts("Setting Flash error");
      v126 = 6;
      if ( !apmib_set(112, &v126) )
        return puts("Setting Flash error");
      v124 = 3;
      if ( !apmib_set(116, &v124) )
        return puts("Setting Flash error");
      v134 = 3;
      if ( !apmib_set(71, &v134) )
        return puts("Setting Flash error");
      v117 = &v135;
      v135 = 2;
    }
    else
    {
      v115 = strlen(v77);
      sub_447990(v77, v147, v115);
      v126 = 1;
      if ( !apmib_set(112, &v126) )
        return puts("Setting Flash error");
      if ( strlen(v77) == 10 )
      {
        v128 = 1;
        if ( !apmib_set(41, &v128) )
          return puts("Setting Flash error");
        v116 = 42;
      }
      else
      {
        v128 = 2;
        if ( !apmib_set(41, &v128) )
          return puts("Setting Flash error");
        v116 = 46;
      }
      if ( !apmib_set(v116, v147) )
        return puts("Setting Flash error");
      v117 = &v134;
      v134 = 1;
    }
    if ( !apmib_set(85, v117) )
      return puts("Setting Flash error");
    goto LABEL_338;
  }
  v3 = (const char *)websGetVar(a1, "setup_finished", "");
  v4 = websGetVar(a1, "wl_ssid", "");
  v5 = (const char *)websGetVar(a1, "wl_ssidforfile", "");
  v6 = (const char *)websGetVar(a1, "formHiddenSSID", "");
  v157 = websGetVar(a1, "wl_rssi", "");
  v156 = (char *)websGetVar(a1, "fromFlag", "");
  if ( strcmp(v6, "formHiddenSSIDpage") )
  {
    v10 = (const char *)websGetVar(a1, "wl_channel", "");
    v120 = strtol(v10, 0, 10);
    v9 = (const char *)websGetVar(a1, "wl_unit", "");
    v11 = (const char *)websGetVar(a1, "wl_bandwidth", "");
    v118 = strtol(v11, 0, 10);
    v150 = (const char *)websGetVar(a1, "wl_bandtype", "");
    v8 = (const char *)websGetVar(a1, "wl_security", "");
    v155 = (char *)websGetVar(a1, "wl_bssid", "");
    switchChan = v120;
    goto LABEL_11;
  }
  puts("===>hidden handler from done Action");
  if ( wlgetHiddenSSIDinfo(v4) )
  {
    strcpy(v136, "2");
    v7 = "ifconfig wlan1-vxd 0.0.0.0";
    goto LABEL_7;
  }
  if ( !wlgetHiddenSSIDinfo5g(v4, 4653056) )
    goto LABEL_360;
  strcpy(v136, "5");
  v7 = "ifconfig wlan0-vxd 0.0.0.0";
LABEL_7:
  system(v7);
  v8 = v137;
  if ( !strcmp("000", outSecType) )
  {
    v150 = outBandType;
    v9 = v136;
    strcpy(v137, "000");
    v155 = "00:00:00:00:00:00";
    v118 = outBandwidth;
    v120 = outChan;
    switchChan = outChan;
LABEL_11:
    if ( !strcmp(v3, "1") )
    {
      v12 = a1;
      v13 = "submit-url-finished";
LABEL_119:
      v63 = websGetVar(v12, v13, "");
      sprintf(v138, "/%s", v63);
LABEL_363:
      v20 = a1;
      v21 = v138;
      return websRedirect(v20, v21);
    }
    v151 = v147;
    memset(v147, 0, sizeof(v147));
    s = v145;
    v153 = (char *)v143;
    sub_447590(v147, v9, off_48EF20[0]);
    v154 = v142;
    memset(v146, 0, sizeof(v146));
    sub_447590(v146, v5, off_48EF24);
    memset(s, 0, 0x64u);
    sub_447590(s, v8, off_48EF20[0]);
    memset(v144, 0, sizeof(v144));
    sub_447590(v144, v150, off_48EF20[0]);
    memset(v153, 0, 0x64u);
    sub_447590(v153, v157, off_48EF20[0]);
    memset(v154, 0, 0x64u);
    sub_447590(v154, v155, off_48EF20[0]);
    sprintf(
      v148,
      "echo %s \"%s\" %s %d %d \"0\" %s 0 %s %s > /var/SiteSurveyResult.var",
      v151,
      v5,
      (const char *)s,
      v120,
      v118,
      (const char *)v144,
      v153,
      (const char *)v154);
    system(v148);
    printf("---> @done action %s Create SiteSurveyResult\n", v148);
    if ( !strcmp(v8, "000") )
    {
      memset(v140, 0, sizeof(v140));
      v14 = CharSpaceAdd(v4);
      sub_447590(v140, v14, off_48EF24);
      memset(v141, 0, sizeof(v141));
      sub_447590(v141, v150, off_48EF24);
      v15 = (const char *)websGetVar(a1, "submit-url-ok", "");
      sprintf(v138, "/%s", v15);
      if ( strcmp(v9, "2") )
      {
        v19 = (const char *)CharSpaceAdd(v4);
        sprintf(v148, "/bin/wlan5bandt.sh wlan0-vxd \"%s\" \"%d\" \"0\" \"0\" \"%d\" \"%s\" &", v19, v120, v118, v141);
        printf("---> Do test 5g = %s\n", v148);
        v18 = "cat /proc/wlan0-vxd/sta_info | grep active | cut -d ' ' -f 7 > /var/sta_info";
      }
      else
      {
        if ( strcmp(v156, "true") )
        {
          v17 = (const char *)CharSpaceAdd(v4);
          sprintf(
            v148,
            "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" \"%d\" \"0\" \"0\" \"%d\" \"%s\" &",
            v17,
            v120,
            v118,
            v141);
          printf("---> Do test 2.4g = %s\n", v148);
        }
        else
        {
          puts("---> iDevice Detected!!");
          v16 = (const char *)CharSpaceAdd(v4);
          sprintf(
            v148,
            "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" \"%d\" \"0\" \"0\" \"%d\" \"%s\" &",
            v16,
            v120,
            v118,
            v141);
          printf("---> Do test 2.4g for iDev= %s\n", v148);
        }
        v18 = "cat /proc/wlan1-vxd/sta_info | grep active | cut -d ' ' -f 7 > /var/sta_info";
      }
      system(v18);
      system(v148);
      v20 = a1;
      v21 = v138;
      return websRedirect(v20, v21);
    }
    v150 = (const char *)websGetVar(a1, "lastOK_password", "");
    v153 = (char *)websGetVar(a1, "lastOK_passwordforFile", "");
    printf("last_password = %s\n", v150);
    if ( *v150 && strcmp(v150, "0") && strcmp(v8, "100") )
    {
      v151 = v141;
      printf("last password exist = %s\n", v150);
      s = v139;
      memset(v151, 0, 0x64u);
      sub_447590(v151, v4, off_48EF24);
      memset(v140, 0, sizeof(v140));
      sub_447590(v140, v150, off_48EF24);
      memset(s, 0, 0x64u);
      sub_447590(s, v153, off_48EF24);
      if ( strcmp(v9, "2") )
      {
        if ( strcmp(v8, "100") )
        {
          if ( strcmp(v8, "001") )
          {
            if ( strcmp(v8, "002") )
            {
              if ( strcmp(v8, "010") )
                v23 = "/bin/wlan5bandt.sh wlan0-vxd \"%s\" %d 5 \"%s\" %d %s &";
              else
                v23 = "/bin/wlan5bandt.sh wlan0-vxd \"%s\" %d 4 \"%s\" %d %s &";
            }
            else
            {
              v23 = "/bin/wlan5bandt.sh wlan0-vxd \"%s\" %d 3 \"%s\" %d %s &";
            }
          }
          else
          {
            v23 = "/bin/wlan5bandt.sh wlan0-vxd \"%s\" %d 2 \"%s\" %d %s &";
          }
        }
        else
        {
          v23 = "/bin/wlan5bandt.sh wlan0-vxd \"%s\" %d 1 \"%s\" %d %s &";
        }
        sprintf(v148, v23, v4, v120, v140, v118, v144);
        v159 = v148;
        system(v148);
        printf("----> The 5g command = %s\n", v159);
        v22 = "cat /proc/wlan0-vxd/sta_info | grep active | cut -d ' ' -f 7 > /var/sta_info";
      }
      else
      {
        if ( strcmp(v156, "true") )
        {
          if ( strcmp(v8, "100") )
          {
            if ( strcmp(v8, "001") )
            {
              if ( strcmp(v8, "002") )
              {
                if ( strcmp(v8, "010") )
                  sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 5 \"%s\" %d %s &", v4, v120, v140, v118, v144);
                else
                  sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 4 \"%s\" %d %s &", v4, v120, v140, v118, v144);
              }
              else
              {
                sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 3 \"%s\" %d %s &", v4, v120, v140, v118, v144);
              }
            }
            else
            {
              sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 2 \"%s\" %d %s &", v4, v120, v140, v118, v144);
            }
          }
          else
          {
            sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 1 \"%s\" %d %s &", v4, v120, v140, v118, v144);
          }
          v159 = v148;
          system(v148);
          printf("----> The 2.4g command = %s\n", v159);
        }
        else
        {
          puts("---> iDevice Detected!!");
          if ( strcmp(v8, "100") )
          {
            if ( strcmp(v8, "001") )
            {
              if ( strcmp(v8, "002") )
              {
                if ( strcmp(v8, "010") )
                  sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 5 \"%s\" %d %s &", v4, v120, v140, v118, v144);
                else
                  sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 4 \"%s\" %d %s &", v4, v120, v140, v118, v144);
              }
              else
              {
                sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 3 \"%s\" %d %s &", v4, v120, v140, v118, v144);
              }
            }
            else
            {
              sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 2 \"%s\" %d %s &", v4, v120, v140, v118, v144);
            }
          }
          else
          {
            sprintf(v148, "/bin/wlan2bandt2.sh wlan1-vxd \"%s\" %d 1 \"%s\" %d %s &", v4, v120, v140, v118, v144);
          }
          v159 = v148;
          system(v148);
          printf("---> Do test 2.4g for iDev= %s\n", v159);
        }
        v22 = "cat /proc/wlan1-vxd/sta_info | grep active | cut -d ' ' -f 7 > /var/sta_info";
      }
      system(v22);
      sprintf(
        v149,
        "echo %s \"%s\" %s %d %d \"%s\" %s 1 %s %s > /var/SiteSurveyResult.var",
        v147,
        v5,
        (const char *)v145,
        v120,
        v118,
        v139,
        (const char *)v144,
        (const char *)v143,
        (const char *)v142);
      printf("---> @SetPassWord %s Create SiteSurveyResult\n", v149);
      system(v149);
      v24 = a1;
      v25 = "submit-url-chkpwd";
    }
    else
    {
      v24 = a1;
      v25 = "submit-url-ok";
    }
    v26 = websGetVar(v24, v25, "");
LABEL_362:
    sprintf(v138, "/%s", v26);
    goto LABEL_363;
  }
  printf("===> outSecType=%s \n", outSecType);
LABEL_70:
  v20 = a1;
  v21 = "/setting_surveyfail.asp";
  return websRedirect(v20, v21);
}'''

    optimizer = TaintAnalysisOptimizer()
    print("=== 报告 ===")
    print(optimizer.generate_analysis_report(sample_code, target_function='system'))
    print("\n=== 优化后代码 ===")
    print(optimizer.optimize_code(sample_code, target_function='system'))


if __name__ == "__main__":
    main()
