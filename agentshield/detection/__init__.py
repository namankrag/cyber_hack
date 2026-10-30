"""Pluggable detection layer.

Each detector scans a tool call's context (and arguments) and returns a
DetectionResult. Detectors are independent and composable — the engine runs
all configured ones and takes the strongest signal. Add a new detector by
subclassing Detector and registering it in build_detectors().
"""
from .base import Detector, build_detectors
from .heuristic import HeuristicDetector

__all__ = ["Detector", "build_detectors", "HeuristicDetector"]
