"""
wifiradar — Device behavioral fingerprinting & probabilistic clustering
for 802.11 management-frame analysis.

Modules:
    fingerprint_engine  — IE fingerprint extraction & confidence scoring
    cluster_engine      — Probabilistic device clustering by fingerprint
    session_engine      — Temporal session correlation across MACs
"""

from .fingerprint_engine import build_ie_fingerprint, compute_confidence
from .cluster_engine import DeviceClusterEngine
from .session_engine import SessionEngine

__all__ = [
    "build_ie_fingerprint",
    "compute_confidence",
    "DeviceClusterEngine",
    "SessionEngine",
]
