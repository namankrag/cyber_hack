"""Detector interface and registry."""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import DetectionResult, ToolCall


class Detector(ABC):
    """A pluggable injection / anomaly detector.

    Keep detectors pure and side-effect free: given a ToolCall, return a
    DetectionResult. Never raise — on failure, return a result with `error`
    set so the engine can apply fail-closed logic instead of crashing.
    """

    name: str = "detector"

    @abstractmethod
    def scan(self, call: ToolCall) -> DetectionResult:  # pragma: no cover - interface
        ...


def build_detectors(config) -> list[Detector]:
    """Instantiate the detectors named in config.detectors.

    Imports are local so that, e.g., the Gemini SDK is only required when the
    LLM detector is actually requested — the heuristic core has zero extra
    dependencies.
    """
    detectors: list[Detector] = []
    for name in config.detectors:
        name = name.strip().lower()
        if name == "heuristic":
            from .heuristic import HeuristicDetector

            detectors.append(HeuristicDetector(threshold=config.injection_threshold))
        elif name == "llm":
            from .llm_detector import LLMDetector

            detectors.append(
                LLMDetector(
                    provider=config.llm_provider,
                    threshold=config.injection_threshold,
                )
            )
        else:
            raise ValueError(f"Unknown detector '{name}'")
    return detectors
