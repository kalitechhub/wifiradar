"""
cluster_engine.py — Probabilistic device clustering by fingerprint hash.

Thread-safe: all mutations go through a threading.Lock.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class Cluster:
    """Mutable cluster record for a unique fingerprint hash."""
    cluster_id: int
    fingerprint_hash: str
    observed_macs: Set[str] = field(default_factory=set)
    seen_ssids: Set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    hit_count: int = 0
    rssi_history: List[float] = field(default_factory=list)
    session_ids: Set[str] = field(default_factory=set)
    confidence_score: float = 0.0

    # Keep RSSI history bounded to avoid unbounded memory growth
    _MAX_RSSI = 500

    def to_dict(self) -> dict:
        """Serialisable dict (sets → lists)."""
        return {
            "cluster_id":        self.cluster_id,
            "fingerprint_hash":  self.fingerprint_hash,
            "observed_macs":     sorted(self.observed_macs),
            "seen_ssids":        sorted(self.seen_ssids),
            "first_seen":        self.first_seen,
            "last_seen":         self.last_seen,
            "hit_count":         self.hit_count,
            "rssi_history":      self.rssi_history[-self._MAX_RSSI:],
            "session_ids":       sorted(self.session_ids),
            "confidence_score":  round(self.confidence_score, 2),
        }


class DeviceClusterEngine:
    """
    Maintains a dictionary of clusters keyed by ``fingerprint_hash``.

    * If a fingerprint already exists → merge into existing cluster.
    * If new → create a new cluster.

    All public methods are thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clusters: Dict[str, Cluster] = {}
        self._next_id: int = 1

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update(
        self,
        fingerprint_hash: str,
        mac: str,
        ssid: Optional[str] = None,
        rssi: Optional[float] = None,
        session_id: Optional[str] = None,
    ) -> Cluster:
        """
        Merge an observation into the appropriate cluster.
        Returns the (possibly new) Cluster object.
        """
        now = time.time()
        mac = (mac or "").lower().strip()

        with self._lock:
            cluster = self._clusters.get(fingerprint_hash)
            if cluster is None:
                # Debug: new fingerprint seen
                # We don't have access to the global logger here easily without circular imports
                # so we can use a simpler print or just trust the caller's debug log.
                cluster = Cluster(
                    cluster_id=self._next_id,
                    fingerprint_hash=fingerprint_hash,
                    first_seen=now,
                )
                self._next_id += 1
                self._clusters[fingerprint_hash] = cluster

            cluster.last_seen = now
            cluster.hit_count += 1
            if mac:
                cluster.observed_macs.add(mac)
            if ssid:
                cluster.seen_ssids.add(ssid)
            if rssi is not None:
                cluster.rssi_history.append(rssi)
                if len(cluster.rssi_history) > Cluster._MAX_RSSI:
                    cluster.rssi_history = cluster.rssi_history[-Cluster._MAX_RSSI:]
            if session_id:
                cluster.session_ids.add(session_id)

            return cluster

    def get_cluster(self, fingerprint_hash: str) -> Optional[Cluster]:
        with self._lock:
            return self._clusters.get(fingerprint_hash)

    def all_clusters(self) -> List[Cluster]:
        with self._lock:
            return list(self._clusters.values())

    def snapshot(self) -> List[dict]:
        """Return a JSON-serialisable snapshot of every cluster."""
        with self._lock:
            return [c.to_dict() for c in self._clusters.values()]

    def dump_json(self, path: str) -> None:
        """Atomically write cluster data to *path*."""
        data = self.snapshot()
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh, indent=2)
        import os
        os.replace(tmp, path)
