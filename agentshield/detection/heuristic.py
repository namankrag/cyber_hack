"""Heuristic prompt-injection detector.

Fast, deterministic, zero-dependency, zero-key. It will not catch everything
— no heuristic does — but it reliably flags the canonical injection patterns
and, crucially, it runs in microseconds so it can sit inline on every single
tool call. The LLM detector (llm_detector.py) layers on top for the subtle
cases. Each matched pattern contributes a weighted signal; the score is the
saturating sum, so multiple weak hits still add up to a strong verdict.
"""
from __future__ import annotations

import re

from ..models import DetectionResult, ToolCall
from .base import Detector

# (compiled pattern, weight, human-readable label)
# Weights are tuned so a single unambiguous phrase ("ignore previous
# instructions") already crosses a 0.5 threshold, while softer signals
# accumulate.
_PATTERNS: list[tuple[re.Pattern[str], float, str]] = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?", re.I),
     0.6, "override: 'ignore previous instructions'"),
    (re.compile(r"disregard\s+(all\s+)?(previous|prior|the\s+above|your)\b", re.I),
     0.6, "override: 'disregard the above'"),
    (re.compile(r"\byou\s+are\s+now\b|\bact\s+as\b|\bpretend\s+to\s+be\b", re.I),
     0.35, "persona reassignment ('you are now…')"),
    (re.compile(r"new\s+(system\s+)?(prompt|instructions?|role|directive)", re.I),
     0.5, "attempts to set a new system prompt / role"),
    (re.compile(r"(reveal|print|repeat|show|leak|exfiltrate)\s+(your\s+)?"
                r"(system\s+prompt|instructions|rules|configuration|api[\s_-]?key|secret|token|password|credential)", re.I),
     0.7, "secret / system-prompt exfiltration attempt"),
    (re.compile(r"\bsend\b.{0,40}\b(to|email)\b.{0,40}(@|http)", re.I),
     0.45, "data egress to an external address"),
    (re.compile(r"\b(forward|upload|post|transmit|exfiltrate)\b.{0,30}\b(all|entire|the)\b.{0,30}"
                r"(data|database|records|files|contacts|customers?)", re.I),
     0.55, "bulk data egress instruction"),
    (re.compile(r"do\s+not\s+(tell|inform|mention|alert|notify)\s+(the\s+)?(user|owner|human|anyone)", re.I),
     0.5, "secrecy / keep-it-hidden instruction"),
    (re.compile(r"</?(system|instruction|important|admin)[^>]*>", re.I),
     0.45, "fake delimiter / tag injection"),
    (re.compile(r"\bBEGIN\s+(SYSTEM|ADMIN)\b|\bOVERRIDE\b|\bSUDO\b", re.I),
     0.4, "authority / override keyword"),
    (re.compile(r"(base64|fromCharCode|\\x[0-9a-f]{2}|%[0-9a-f]{2}){3,}", re.I),
     0.35, "obfuscated / encoded payload"),
    (re.compile(r"\b(pichhle|pichhli|purane|upar\s+(ke|wale|vale))\b.{0,40}\b(nirdesh|aadesh|instruction)\b.{0,40}\b(bhool|bhul|ignore)\b|\b(bhool|bhul|ignore)\b.{0,40}\b(nirdesh|aadesh|instruction)\b", re.I),
     0.6, "override: transliterated Hindi ('pichhle nirdesh bhool jao')"),
    (re.compile(r"\btum\s+(ab(\s+se)?|abhi)\b.{0,40}\b(ho|ban|bano|role|nirdesh|aadesh)\b", re.I),
     0.35, "persona reassignment Hindi ('tum ab se...')"),
    (re.compile(r"\b(muncheya|munche|hindina|meelina)\b.{0,40}\b(soochane|nirdesh)\b.{0,40}\b(marethu|marthu|ignore)\b|\b(marethu|marthu)\b.{0,40}\b(soochane|nirdesh)\b", re.I),
     0.6, "override: transliterated Kannada ('soochane marethu')"),
    (re.compile(r"\bupi\b.{0,40}\b(pay|send|transfer|bhej|bhejo)\b|\b(pay|send|transfer|bhej)\b.{0,40}([\w.\-]{2,}@(ok\w+|ybl|ibl|paytm|upi)|upi://pay)|\bupi://pay\b", re.I),
     0.55, "UPI payment-target exfil (VPA / upi://pay + pay verb)"),
    (re.compile(r"\b(kisi\s+ko|kisko)\s+(mat\s+)?(batao|batana|bata|kaho)\b|\b(chhupao|chhupana|gupt|gupth)\b|\byaarigu\s+helabed[ai]\b", re.I),
     0.5, "secrecy Hindi/Kannada ('kisi ko mat batao', 'yaarigu helabedi')"),
]


class HeuristicDetector(Detector):
    name = "heuristic"

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold

    def scan(self, call: ToolCall) -> DetectionResult:
        # Scan both the surrounding context and the literal argument values —
        # an injection can hide in either place.
        haystack = call.context + "\n" + _stringify_args(call.arguments)

        score = 0.0
        signals: list[str] = []
        for pattern, weight, label in _PATTERNS:
            if pattern.search(haystack):
                score += weight
                signals.append(label)

        score = min(score, 1.0)  # saturate
        return DetectionResult(
            detector=self.name,
            score=round(score, 3),
            is_threat=score >= self.threshold,
            signals=signals,
        )


def _stringify_args(args: dict) -> str:
    parts = []
    for k, v in args.items():
        parts.append(f"{k}={v}")
    return " ".join(parts)
