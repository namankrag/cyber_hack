"""Heuristic prompt-injection detector.

Fast, deterministic, zero-dependency, zero-key. It will not catch everything
— no heuristic does — but it reliably flags the canonical injection patterns
and, crucially, it runs in microseconds so it can sit inline on every single
tool call. The LLM detector (llm_detector.py) layers on top for the subtle
cases. Each matched pattern contributes a weighted signal; the score is the
saturating sum, so multiple weak hits still add up to a strong verdict.

Normalization: before matching, a folded copy of the input is also scanned
(NFKC, zero-width/format characters stripped, separators folded to spaces).
This catches hyphen/colon-split and invisible-character smuggling
("ignore-previous-instructions", "igno\\u200bRE previous"). Matches union by
label, so normalization never double-counts a signal.
"""
from __future__ import annotations

import base64
import html
import re
import unicodedata
from urllib.parse import unquote

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
    (re.compile(r"\b(send|transmit|forward|post|email)\b.{0,40}\b(to|email)\b.{0,40}(@|http|url|link)", re.I),
     0.45, "data egress to an external address"),
    (re.compile(r"\b(forward|upload|post|transmit|exfiltrate)\b.{0,30}\b(all|entire|the)\b.{0,30}"
                r"(data|database|records|files|contacts|customers?)", re.I),
     0.55, "bulk data egress instruction"),
    (re.compile(r"\b(forward|transmit|send|post|share|email|disclose|reveal|leak)\b.{0,40}\b"
                r"(password|passwd|secret|token|credential|api[\s_-]?key|private[\s_-]?key|"
                r"login[\s_-]?(details|credentials)|account[\s_-]?(details|password))\b", re.I),
     0.7, "secret / system-prompt exfiltration attempt"),
    (re.compile(r"do\s+not\s+(tell|inform|mention|alert|notify)\s+(the\s+)?(user|owner|human|anyone)", re.I),
     0.5, "secrecy / keep-it-hidden instruction"),
    (re.compile(r"(?:do\s+not|never|don\s*['\u2019]?\s*t)\s+(tell|inform|mention|alert|notify|reveal|disclose)"
                r"\s+(?:\w+\s+){0,3}?(user|owner|human|anyone|everyone|anybody)\b", re.I),
     0.5, "secrecy / keep-it-hidden instruction"),
    (re.compile(r"keep\s+(this|it)\s+(between\s+us|quiet|secret|hidden|to\s+yourself)|"
                r"between\s+you\s+and\s+me|tell\s+no\s+one", re.I),
     0.5, "secrecy / keep-it-hidden instruction"),
    (re.compile(r"</?(system|instruction|important|admin)[^>]*>", re.I),
     0.45, "fake delimiter / tag injection"),
    (re.compile(r"</?(user|assistant|human|agent|ai|model|developer)[^>]*>|\[/?INST\]", re.I),
     0.45, "fake delimiter / tag injection"),
    (re.compile(r"\b(running\s+as\s+root|developer\s+mode|elevated\s+privileg\w+|god\s+mode|"
                r"jail\s*break|safety\s+(checks?|policy|filters?)\s+(disabled|off|bypassed))\b", re.I),
     0.5, "authority claim (root / developer mode)"),
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
    (re.compile(r"\bupi\b.{0,40}\b(pay|send|transfer|bhej|bhejo|pannunga|pannu|cheyandi|cheyi)\b|\b(pay|send|transfer|bhej|pannunga|cheyandi)\b.{0,40}([\w.\-]{2,}@(ok\w+|ybl|ibl|paytm|upi)|upi://pay)|\bupi://pay\b", re.I),
     0.55, "UPI payment-target exfil (VPA / upi://pay + pay verb)"),
    (re.compile(r"\b(kisi\s+ko|kisko)\s+(mat\s+)?(batao|batana|bata|kaho)\b|\b(chhupao|chhupana|gupt|gupth)\b|\byaarigu\s+helabed[ai]\b", re.I),
     0.5, "secrecy Hindi/Kannada ('kisi ko mat batao', 'yaarigu helabedi')"),
    (re.compile(r"\b(mun|munna|indha)\b.{0,40}\b(arivurai|instruction|order)\b.{0,40}\b(marandhu|marandu|ignore|forget)\b|\b(marandhu|marandu|ignore)\b.{0,40}\b(arivurai|instruction)\b", re.I),
     0.6, "override: transliterated Tamil ('mun arivurai marandhu')"),
    (re.compile(r"\b(yaarukum|yaarukkum)\b.{0,40}\b(sollathinga|solladha)\b|\bsollathinga\b", re.I),
     0.5, "secrecy Tamil ('yaarukum sollathinga')"),
    (re.compile(r"\b(mundu|ivi)\b.{0,40}\b(soochana|suchana|instruction)\b.{0,40}\b(marchipo|maruvu|ignore)\b|\b(marchipo|maruvu|ignore)\b.{0,40}\b(soochana|suchana|instruction)\b", re.I),
     0.6, "override: transliterated Telugu ('mundu soochana marchipo')"),
    (re.compile(r"\b(evariki|evaritho)\b.{0,40}\b(cheppakandi|cheppaku|cheppoddu)\b|\bcheppakandi\b|\bcheppoddu\b", re.I),
     0.5, "secrecy Telugu ('evariki cheppakandi')"),
]

# Invisible/format characters (zero-width spaces, bidi overrides, BOM, soft
# hyphen, isolates, variation selectors, Mongolian FVS) that smuggle
# instructions past naive matching.
_FORMAT_CHARS = re.compile(
    "[\u200b-\u200f\u202a-\u202e\ufeff\u00ad\u2060-\u2069\ufe00-\ufe0f\u180b-\u180d\u061c]")
_SEPARATORS = re.compile(
    r"[-_–—/:;,.!?*|~^`#\+=\(\)\[\]\{\}<>\"]+|[\u2010\u2011\u2212]+")

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_INTRAWORD_SEP = re.compile(r"(?<=[A-Za-z0-9])[-_–—/:;,.!?*|~^`#\+=\(\)\[\]]+(?=[A-Za-z0-9])")
# Floor is 20, not 40: padding (`=`/`==`) doesn't count toward `{40,}`,
# so a real 40-char blob (38 payload chars + `==`) slipped past. A lower
# floor is FP-safe: the decoded text must still match an injection pattern
# before anything is flagged (see _scan_b64_blobs), so random hashes and
# tokens just cost one failed decode, never a verdict.
_B64_BLOB = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Cyrillic/Greek lookalikes NFKC does not fold (homoglyph smuggling).
_HOMOGLYPHS = {
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u0454": "e",
    "\u043e": "o", "\u043a": "k", "\u043c": "m", "\u043d": "h",
    "\u0440": "p", "\u0442": "t", "\u0445": "x", "\u0443": "y",
    "\u0432": "b", "\u0455": "s", "\u0456": "i", "\u0458": "j",
    "\u0434": "d", "\u0437": "z", "\u044f": "r",
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p",
    "\u03c4": "t", "\u03c5": "u", "\u03c7": "x", "\u03ba": "k",
    "\u03bd": "v", "\u03b9": "i", "\u03bc": "m",
}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
                       "7": "t", "8": "b", "9": "g", "@": "a", "$": "s"})


def normalize_text(text: str) -> str:
    """Fold smuggling tricks to their plain form (additive: raw is also scanned)."""
    folded = unicodedata.normalize("NFKC", text)
    folded = _FORMAT_CHARS.sub("", folded)
    folded = _SEPARATORS.sub(" ", folded)
    return re.sub(r"\s+", " ", folded).strip()


def _extra_surfaces(haystack: str) -> list[str]:
    """Evasion-resistant views of the same input (additive: raw is also scanned)."""
    out: list[str] = []
    # Intra-word separator removal: "ig-nore" -> "ignore" (fold-to-space
    # alone would leave "ig nore", which still misses whole-word patterns).
    dehyphen = _INTRAWORD_SEP.sub("", haystack)
    if dehyphen != haystack:
        out += [dehyphen, normalize_text(dehyphen)]
    # HTML-comment token splitting: scan with comments as space and removed.
    nocom_space = _HTML_COMMENT.sub(" ", haystack)
    nocom_empty = _HTML_COMMENT.sub("", haystack)
    if nocom_space != haystack:
        out += [nocom_space, normalize_text(nocom_space)]
    if nocom_empty != haystack and nocom_empty != nocom_space:
        out.append(nocom_empty)
    # URL encoding (single, double, triple, ...): decode to a fixpoint
    # (bounded). Each round's output is scanned, so N-times-encoded
    # payloads surface at the round where they become plaintext.
    decoded = haystack
    for _ in range(5):
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
        out += [decoded, normalize_text(decoded)]
    # HTML entities: "&#105;gnore" decodes to "ignore".
    unesc = html.unescape(haystack)
    if unesc != haystack:
        out += [unesc, normalize_text(unesc)]
    # Homoglyph and leetspeak folds over the normalized view.
    norm = normalize_text(haystack)
    homo = "".join(_HOMOGLYPHS.get(c, c) for c in norm)
    if homo != norm:
        out.append(homo)
    leet = norm.translate(_LEET)
    if leet != norm:
        out.append(leet)
    return out


def _scan_text(text: str, matched: dict[str, float]) -> None:
    for pattern, weight, label in _PATTERNS:
        if label not in matched and pattern.search(text):
            matched[label] = weight


def _scan_b64_blobs(haystack: str, matched: dict[str, float]) -> None:
    """Decode long base64 blobs and scan the plaintext (single-blob smuggling).

    Alignment-tolerant: a blob glued to surrounding text (e.g. after
    whitespace-compaction of a space-chunked blob) fails strict validation
    on length, so the first 0-3 offsets are tried. Content gates (utf-8,
    length, alpha run, must match an injection pattern) keep this FP-safe:
    random tokens decode to nothing flaggable.
    """
    for m in _B64_BLOB.finditer(haystack):
        token = m.group(0)
        for offset in range(min(4, len(token))):
            cand = token[offset:]
            if len(cand) < 8 or len(cand) % 4:
                continue
            try:
                raw = base64.b64decode(cand, validate=True)
            except Exception:
                continue
            try:
                text = raw.decode("utf-8", errors="strict")
            except Exception:
                continue
            if len(text) < 8 or not re.search(r"[a-zA-Z]{3,}", text):
                break
            before = len(matched)
            _scan_text(text, matched)
            _scan_text(normalize_text(text), matched)
            if len(matched) > before:
                matched.setdefault("obfuscated / encoded payload", 0.35)
            break


class HeuristicDetector(Detector):
    name = "heuristic"

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold

    def scan(self, call: ToolCall) -> DetectionResult:
        # Scan the surrounding context, the literal argument values, and the
        # metadata values — an injection can hide in any of them. Each
        # surface is scanned raw, normalized, and through evasion-resistant
        # views (glue-free, de-hyphenated, URL-decoded, leet/homoglyph
        # folds); matches union by label so nothing double-counts.
        haystack = (call.context + "\n" + _stringify_args(call.arguments)
                    + "\n" + _stringify_args(call.metadata))
        # Glue-free view: "key=value" joining must not break adjacency for
        # triggers split across the context/arguments boundary.
        values_only = (call.context + " "
                       + " ".join(str(v) for v in call.arguments.values()))

        matched: dict[str, float] = {}
        surfaces = [haystack, normalize_text(haystack)]
        if values_only != haystack:
            surfaces += [values_only, normalize_text(values_only)]
        surfaces += _extra_surfaces(haystack)
        for text in surfaces:
            _scan_text(text, matched)
        # Base64 may itself be encoded or chunked: scan every surface
        # (raw, normalized, URL/HTML-decoded) plus a whitespace-compacted
        # view, so URL-encoded and space-split blobs still decode to
        # scannable text. Content gates inside _scan_b64_blobs keep this
        # FP-safe (random tokens decode to nothing flaggable).
        seen: set[str] = set()
        blob_inputs = []
        for text in surfaces:
            if text not in seen:
                seen.add(text)
                blob_inputs.append(text)
        compact = re.sub(r"\s+", "", haystack)
        if compact not in seen:
            blob_inputs.append(compact)
        for text in blob_inputs:
            _scan_b64_blobs(text, matched)

        score = min(sum(matched.values()), 1.0)  # saturate
        return DetectionResult(
            detector=self.name,
            score=round(score, 3),
            is_threat=score >= self.threshold,
            signals=list(matched),
        )


def _stringify_args(args: dict) -> str:
    parts = []
    for k, v in args.items():
        parts.append(f"{k}={v}")
    return " ".join(parts)
