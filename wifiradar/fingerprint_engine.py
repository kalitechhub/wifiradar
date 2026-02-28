"""
fingerprint_engine.py — Information Element (IE) fingerprinting and
confidence scoring for 802.11 management frames.

All hashing uses SHA-256 and is MAC-address independent.
"""

from __future__ import annotations

import hashlib
import json
import statistics
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# 1️⃣  IE Fingerprint Builder
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IEFingerprint:
    """Immutable fingerprint derived from a single 802.11 mgmt frame."""
    ie_order_hash: str
    capability_hash: str
    full_fingerprint_hash: str
    raw_elements: Dict[str, Any] = field(default_factory=dict, hash=False)

    def to_dict(self) -> dict:
        return asdict(self)


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()


def _extract_ie_list(packet) -> List[dict]:
    """Walk the Dot11Elt chain and return an ordered list of IE dicts."""
    from scapy.all import Dot11Elt  # local import to keep module importable w/o scapy at load

    ies: List[dict] = []
    elt = packet.getlayer(Dot11Elt)
    while elt:
        ie: Dict[str, Any] = {
            "id": elt.ID,
            "len": elt.len if hasattr(elt, "len") else 0,
        }
        try:
            ie["info"] = elt.info.hex() if isinstance(elt.info, bytes) else str(elt.info)
        except Exception:
            ie["info"] = ""
        ies.append(ie)
        # advance
        try:
            elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            break
    return ies


def _parse_supported_rates(ies: List[dict]) -> List[float]:
    """IE IDs 1 (Supported Rates) and 50 (Extended Supported Rates)."""
    rates: List[float] = []
    for ie in ies:
        if ie["id"] in (1, 50) and ie["info"]:
            try:
                raw = bytes.fromhex(ie["info"])
                for b in raw:
                    rates.append((b & 0x7F) * 0.5)
            except Exception:
                pass
    return sorted(rates)


def _parse_ht_capabilities(ies: List[dict]) -> Optional[str]:
    """IE ID 45 — HT Capabilities."""
    for ie in ies:
        if ie["id"] == 45 and ie["info"]:
            return ie["info"]
    return None


def _parse_vht_capabilities(ies: List[dict]) -> Optional[str]:
    """IE ID 191 — VHT Capabilities."""
    for ie in ies:
        if ie["id"] == 191 and ie["info"]:
            return ie["info"]
    return None


def _parse_he_capabilities(ies: List[dict]) -> Optional[str]:
    """IE ID 255 with Extension IE ID 35 — HE Capabilities.
    Simplified: return raw hex of first ID-255 element that is long enough."""
    for ie in ies:
        if ie["id"] == 255 and ie["info"] and len(ie["info"]) > 4:
            return ie["info"]
    return None


def _parse_extended_capabilities(ies: List[dict]) -> Optional[str]:
    """IE ID 127 — Extended Capabilities."""
    for ie in ies:
        if ie["id"] == 127 and ie["info"]:
            return ie["info"]
    return None


def _parse_rsn(ies: List[dict]) -> Optional[str]:
    """IE ID 48 — RSN (Robust Security Network)."""
    for ie in ies:
        if ie["id"] == 48 and ie["info"]:
            return ie["info"]
    return None


def _parse_vendor_specific(ies: List[dict]) -> List[str]:
    """IE ID 221 — Vendor Specific elements."""
    return [ie["info"] for ie in ies if ie["id"] == 221 and ie["info"]]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_ie_fingerprint(packet) -> Optional[IEFingerprint]:
    """
    Build a MAC-independent fingerprint from a Scapy Dot11 Probe/Assoc
    Request packet.

    Returns ``None`` if the packet has no Dot11Elt layer.
    """
    from scapy.all import Dot11Elt  # deferred import

    if not packet.haslayer(Dot11Elt):
        return None

    ies = _extract_ie_list(packet)
    if not ies:
        return None

    # --- ordered IE IDs ---
    ie_ids = [ie["id"] for ie in ies]
    ie_order_hash = _sha256(",".join(str(i) for i in ie_ids))

    # --- capability components ---
    supported_rates = _parse_supported_rates(ies)
    ht_cap   = _parse_ht_capabilities(ies)
    vht_cap  = _parse_vht_capabilities(ies)
    he_cap   = _parse_he_capabilities(ies)
    ext_cap  = _parse_extended_capabilities(ies)
    rsn      = _parse_rsn(ies)
    vendor   = _parse_vendor_specific(ies)

    cap_blob = json.dumps({
        "rates": supported_rates,
        "ht":    ht_cap,
        "vht":   vht_cap,
        "he":    he_cap,
        "ext":   ext_cap,
        "rsn":   rsn,
    }, sort_keys=True)
    capability_hash = _sha256(cap_blob)

    raw_elements: Dict[str, Any] = {
        "ie_ids":           ie_ids,
        "supported_rates":  supported_rates,
        "ht_capabilities":  ht_cap,
        "vht_capabilities": vht_cap,
        "he_capabilities":  he_cap,
        "extended_capabilities": ext_cap,
        "rsn":              rsn,
        "vendor_specific":  vendor,
    }

    # IMPORTANT: We purposefully exclude "vendor_specific" from the
    # hash payload because it frequently contains shifting timestamps or Apple Continuity hashes
    # that ruin device grouping/clustering. We preserve it in raw_elements for display only.
    hashable_elements = {
        "supported_rates":  supported_rates,
        "ht_capabilities":  ht_cap,
        "vht_capabilities": vht_cap,
        "he_capabilities":  he_cap,
        "extended_capabilities": ext_cap,
        "rsn":              rsn,
    }

    full_blob = json.dumps(hashable_elements, sort_keys=True, default=str)
    full_fingerprint_hash = _sha256(full_blob)

    try:
        with open("/tmp/fp_trace.txt", "a") as dbg:
            dbg.write(f"MAC: {packet.addr2} HASH: {full_fingerprint_hash}\n{full_blob}\n\n")
    except: pass

    return IEFingerprint(
        ie_order_hash=ie_order_hash,
        capability_hash=capability_hash,
        full_fingerprint_hash=full_fingerprint_hash,
        raw_elements=raw_elements,
    )


# ---------------------------------------------------------------------------
# 4️⃣  Confidence Scoring
# ---------------------------------------------------------------------------

def compute_confidence(cluster: dict) -> float:
    """
    Return a 0–100 confidence score for a cluster dict.

    Score components
    ----------------
    +40  fingerprint consistent across multiple MACs
    +20  seen across multiple sessions
    +15  seen probing multiple SSIDs
    +10  RSSI variance small (≤ 8 dB → full, ≤ 15 dB → half)
    +15  vendor OUI consistent across observed MACs
    """
    score = 0.0

    # --- multi-MAC consistency ---
    observed_macs = cluster.get("observed_macs", set())
    if len(observed_macs) >= 2:
        score += 40.0

    # --- multi-session ---
    sessions = cluster.get("session_ids", set())
    if len(sessions) >= 2:
        score += 20.0

    # --- SSID diversity ---
    ssids = cluster.get("seen_ssids", set())
    if len(ssids) >= 2:
        score += 15.0

    # --- RSSI stability ---
    rssi_hist = [r for r in cluster.get("rssi_history", []) if isinstance(r, (int, float))]
    if len(rssi_hist) >= 3:
        sd = statistics.stdev(rssi_hist)
        if sd <= 8:
            score += 10.0
        elif sd <= 15:
            score += 5.0

    # --- vendor OUI consistency ---
    if observed_macs:
        ouis = {m[:8] for m in observed_macs if len(m) >= 8}
        if len(ouis) == 1:
            score += 15.0

    return min(score, 100.0)
