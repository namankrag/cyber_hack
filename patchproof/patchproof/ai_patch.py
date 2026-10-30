"""AI-assisted patch generation — proposes a fix, the gate decides.

This is the honest way to use an LLM in security tooling: let it *write* a
candidate patch, but never trust it. The generated code is fed through the exact
same verification gate as a curated patch (exploit must be blocked AND the
regression suite must stay green). If the AI's fix fails either check, it is
rejected and the pipeline falls back to the curated patch. A missing API key
simply means no AI candidate is produced — never a weaker result.

Providers: "gemini" (Google AI Studio free tier) or "groq" (free tier).
Reads GEMINI_API_KEY / GROQ_API_KEY from the environment (.env supported).

Safety: the candidate is parsed and validated (must be valid Python and must
still define the same function) before it is ever executed by the verifier.
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path

_PROMPT = """You are a secure-coding assistant. Below is a single Python \
function from a Flask app that contains a {cwe} vulnerability. Rewrite the \
function to fix ONLY that vulnerability, preserving its name, signature, and \
all legitimate behaviour. Return ONLY the corrected function as Python code, \
with no explanation and no markdown fences.

VULNERABILITY: {cwe} ({rule_id})

FUNCTION:
{func_src}
"""


class AIPatcher:
    def __init__(self, provider: str | None = None, timeout_s: float = 20.0,
                 model: str | None = None) -> None:
        self.provider = (provider or os.getenv("PATCHPROOF_AI_PROVIDER", "gemini")).lower()
        self.timeout_s = timeout_s
        self.model = model

    # --- availability ------------------------------------------------------
    def available(self) -> bool:
        if self.provider == "gemini":
            return bool(os.getenv("GEMINI_API_KEY"))
        if self.provider == "groq":
            return bool(os.getenv("GROQ_API_KEY"))
        return False

    # --- main entry --------------------------------------------------------
    def propose(self, target_file: str | Path, rule_id: str,
                line: int) -> str | None:
        """Return a candidate patched *file source*, or None on any failure."""
        source = Path(target_file).read_text()
        span = _function_span(source, line)
        if span is None:
            return None
        start, end, func_src, func_name = span

        cwe = {"sqli": "CWE-89 SQL injection", "cmdi": "CWE-78 command injection",
               "pathtrav": "CWE-22 path traversal", "idor": "CWE-639 IDOR",
               "xss": "CWE-79 reflected XSS"}.get(rule_id, rule_id)
        prompt = _PROMPT.format(cwe=cwe, rule_id=rule_id, func_src=func_src)

        try:
            import concurrent.futures as cf
            with cf.ThreadPoolExecutor(max_workers=1) as ex:
                raw = ex.submit(self._complete, prompt).result(timeout=self.timeout_s)
        except Exception:  # noqa: BLE001 - any failure -> no candidate
            return None

        new_func = _extract_code(raw)
        if not _is_valid_function(new_func, func_name):
            return None

        # Splice the new function back into the file, preserving indentation.
        new_func = _reindent(new_func, func_src)
        lines = source.splitlines(keepends=True)
        patched = "".join(lines[:start]) + new_func + "".join(lines[end:])
        # Final guard: the whole file must still parse.
        try:
            ast.parse(patched)
        except SyntaxError:
            return None
        return patched

    # --- providers ---------------------------------------------------------
    def _complete(self, prompt: str) -> str:
        if self.provider == "gemini":
            from google import genai
            client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
            resp = client.models.generate_content(
                model=self.model or "gemini-2.0-flash", contents=prompt)
            return resp.text or ""
        if self.provider == "groq":
            from groq import Groq
            client = Groq(api_key=os.environ["GROQ_API_KEY"])
            resp = client.chat.completions.create(
                model=self.model or "llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}], temperature=0)
            return resp.choices[0].message.content or ""
        raise ValueError(f"unknown provider {self.provider}")


# --------------------------------------------------------------------------
def _function_span(source: str, line: int):
    """Return (start_idx, end_idx, func_source, name) for the INNERMOST function
    that contains `line` (0-based slice indices into source lines)."""
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    containing = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.lineno <= line <= n.end_lineno
    ]
    if not containing:
        return None
    # Innermost = the smallest span that contains the line.
    node = min(containing, key=lambda n: n.end_lineno - n.lineno)
    start, end = node.lineno - 1, node.end_lineno
    return start, end, "".join(lines[start:end]), node.name


def _extract_code(raw: str) -> str:
    m = re.search(r"```(?:python)?\s*(.*?)```", raw, re.S)
    code = m.group(1) if m else raw
    return code.strip("\n")


def _is_valid_function(code: str, name: str) -> bool:
    import textwrap
    if not code.strip():
        return False
    try:
        tree = ast.parse(textwrap.dedent(code))
    except SyntaxError:
        return False
    return any(isinstance(n, ast.FunctionDef) and n.name == name
               for n in ast.walk(tree))


def _reindent(new_func: str, original_func: str) -> str:
    """Match the original function's leading indentation."""
    orig_indent = len(original_func) - len(original_func.lstrip(" "))
    new_lines = new_func.splitlines()
    cur_indent = len(new_lines[0]) - len(new_lines[0].lstrip(" ")) if new_lines else 0
    shift = orig_indent - cur_indent
    if shift > 0:
        new_func = "\n".join((" " * shift) + ln if ln else ln for ln in new_lines)
    if not new_func.endswith("\n"):
        new_func += "\n"
    return new_func
