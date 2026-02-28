"""
session_engine.py — Temporal session correlation across MAC addresses.

Session rules
-------------
* Same MAC within ``SESSION_GAP`` seconds → same session.
* Gap > ``SESSION_GAP`` → new session.
* Different MAC but same fingerprint hash → sessions are merged.

Thread-safe via ``threading.Lock``.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional, Set


SESSION_GAP = 300  # 5 minutes


@dataclass
class Session:
    """A single observation session."""
    session_id: str
    macs: Set[str] = field(default_factory=set)
    start_time: float = field(default_factory=time.time)
    end_time: float = field(default_factory=time.time)
    fingerprints: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "session_id":   self.session_id,
            "macs":         sorted(self.macs),
            "start_time":   self.start_time,
            "end_time":     self.end_time,
            "fingerprints": sorted(self.fingerprints),
        }


class SessionEngine:
    """
    Assigns observations to sessions and supports cross-MAC merging
    when the same fingerprint is detected from different MACs.
    """

    def __init__(self, gap: float = SESSION_GAP) -> None:
        self._lock = threading.Lock()
        self._gap = gap
        # mac -> active session id
        self._mac_session: Dict[str, str] = {}
        # session_id -> Session
        self._sessions: Dict[str, Session] = {}
        # fingerprint_hash -> session_id (for cross-MAC merge)
        self._fp_session: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assign_session(
        self,
        mac: str,
        timestamp: float,
        fingerprint_hash: Optional[str] = None,
    ) -> str:
        """
        Assign a session ID for the given *mac* at *timestamp*.

        If *fingerprint_hash* is provided and another session with the
        same fingerprint exists, the sessions are merged.

        Returns the session ID.
        """
        mac = (mac or "").lower().strip()

        with self._lock:
            existing_sid = self._mac_session.get(mac)
            session: Optional[Session] = None

            if existing_sid and existing_sid in self._sessions:
                session = self._sessions[existing_sid]
                if (timestamp - session.end_time) <= self._gap:
                    # Continue existing session
                    session.end_time = timestamp
                    session.macs.add(mac)
                    if fingerprint_hash:
                        session.fingerprints.add(fingerprint_hash)
                        self._try_merge(session, fingerprint_hash)
                    return session.session_id
                # Gap exceeded → new session
                session = None

            # Cross-MAC merge: if fingerprint already maps to a session
            if fingerprint_hash and fingerprint_hash in self._fp_session:
                fp_sid = self._fp_session[fingerprint_hash]
                if fp_sid in self._sessions:
                    fp_session = self._sessions[fp_sid]
                    if (timestamp - fp_session.end_time) <= self._gap:
                        fp_session.end_time = timestamp
                        fp_session.macs.add(mac)
                        fp_session.fingerprints.add(fingerprint_hash)
                        self._mac_session[mac] = fp_sid
                        return fp_sid

            # Create new session
            sid = uuid.uuid4().hex[:12]
            session = Session(
                session_id=sid,
                macs={mac},
                start_time=timestamp,
                end_time=timestamp,
                fingerprints={fingerprint_hash} if fingerprint_hash else set(),
            )
            self._sessions[sid] = session
            self._mac_session[mac] = sid
            if fingerprint_hash:
                self._fp_session[fingerprint_hash] = sid
            return sid

    def get_session(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)

    def all_sessions(self) -> list:
        with self._lock:
            return [s.to_dict() for s in self._sessions.values()]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _try_merge(self, session: Session, fingerprint_hash: str) -> None:
        """Merge another session with the same fingerprint into *session*."""
        other_sid = self._fp_session.get(fingerprint_hash)
        if other_sid and other_sid != session.session_id and other_sid in self._sessions:
            other = self._sessions[other_sid]
            # Absorb other into session
            session.macs.update(other.macs)
            session.fingerprints.update(other.fingerprints)
            session.start_time = min(session.start_time, other.start_time)
            session.end_time = max(session.end_time, other.end_time)
            # Re-point all MACs that pointed to other
            for m in other.macs:
                self._mac_session[m] = session.session_id
            # Re-point fingerprints
            for fp in other.fingerprints:
                self._fp_session[fp] = session.session_id
            del self._sessions[other_sid]

        # Always record mapping
        self._fp_session[fingerprint_hash] = session.session_id
