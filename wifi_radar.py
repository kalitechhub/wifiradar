#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wifi_radar.py  —  Single-radio client-only Wi-Fi radar with web dashboard

• Uses Alfa (monitor mode) to sniff client-ish mgmt frames only
  (ProbeReq, AssocReq, ReassocReq, Auth, Disassoc, Deauth)
• Channel hopping across 2.4GHz + 5GHz
• Leaves onboard Wi-Fi alone for your internet
• Timestamped CSV + PCAP + JSON logging (no duplicate rows)
• Live React dashboard auto-opens at http://localhost:8080

Run:
  sudo python3 wifi_radar.py start
  sudo python3 wifi_radar.py stop
"""

import os, sys, time, csv, json, signal, subprocess, threading, queue, getpass, copy, datetime, logging, traceback, webbrowser
from pathlib import Path

# ---------- BEHAVIORAL FINGERPRINTING & CLUSTERING ----------
from wifiradar.fingerprint_engine import build_ie_fingerprint, compute_confidence
from wifiradar.cluster_engine import DeviceClusterEngine
from wifiradar.session_engine import SessionEngine
from wifiradar.web_dashboard import start_dashboard

# ---------- SCAPY (top-level with friendly error) ----------
try:
    from scapy.all import sniff, Dot11, Dot11Elt
    from scapy.error import Scapy_Exception
except ImportError:
    print("ERROR: scapy is required.  Install with:  pip install scapy")
    sys.exit(1)

# ---------- SETTINGS ----------
ALFA_IFACE_DEFAULT = "wlx00c0cab4b4f0"   # primary Alfa adapter (hardcoded, tried first)

def _iface_exists(name):
    """Return True if the named network interface is visible to the OS."""
    return subprocess.run(f"ip link show {name}", shell=True,
                          capture_output=True, text=True).returncode == 0

def _is_usb_wifi(iface):
    """
    Return True if 'iface' is a USB wireless adapter.
    Checks the sysfs device symlink — USB adapters always resolve through
    a '/usb' component in their path, while PCI/onboard cards do not.
    Works on any Linux machine regardless of interface naming.
    """
    try:
        dev_path = Path(f"/sys/class/net/{iface}/device").resolve()
        return "/usb" in str(dev_path)
    except Exception:
        return False

def _detect_alfa():
    """
    Select the monitor adapter, always skipping onboard/PCI adapters.

    Onboard detection is bus-type based (sysfs), so it works on any machine
    regardless of whether the onboard is wlp2s0, wlan0, wlp3s0, etc.

    Priority:
      1. wlx00c0cab4b4f0  – the hardcoded Alfa (tried first)
      2. Auto-detect      – any USB wireless adapter that is not the
                            hardcoded Alfa (local Alfa fallback)
    """
    # 1) Try the hardcoded Alfa name first
    if _iface_exists(ALFA_IFACE_DEFAULT):
        print(f"[detect] Using primary Alfa adapter: '{ALFA_IFACE_DEFAULT}'")
        return ALFA_IFACE_DEFAULT

    # 2) Auto-detect — any USB wireless iface (onboard/PCI adapters are skipped)
    print(f"[detect] '{ALFA_IFACE_DEFAULT}' not found, scanning for any USB Wi-Fi adapter…")
    try:
        out = subprocess.run("iw dev", shell=True, capture_output=True, text=True).stdout
        usb_ifaces = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                iface = line.split()[1]
                if iface == ALFA_IFACE_DEFAULT:
                    continue  # already tried above
                if _is_usb_wifi(iface):
                    usb_ifaces.append(iface)
                else:
                    print(f"[detect] Skipping '{iface}' (onboard/PCI adapter)")
        if usb_ifaces:
            print(f"[detect] Found USB adapter(s): {usb_ifaces} — using '{usb_ifaces[0]}' as fallback")
            return usb_ifaces[0]
    except Exception as e:
        print(f"[detect] auto-detect error: {e}")

    # 3) Nothing found
    print("[detect] ERROR: No suitable USB Wi-Fi adapter found.")
    print("         Plug in your Alfa adapter and try again.")
    print(f"         Expected: {ALFA_IFACE_DEFAULT}")
    sys.exit(1)

ALFA_IFACE = _detect_alfa()
# Keep a reference so stop_flow() can restore the correct interface name
ONBOARD_IFACE = "wlp2s0"   # informational only — actual exclusion is bus-type based


def ensure_dependencies():
    """Checks for required system/pip packages and installs them if missing."""
    import subprocess
    import sys
    print("[install] Checking system dependencies...")
    sys_missing = []
    if subprocess.run("which tcpdump", shell=True, capture_output=True).returncode != 0:
        sys_missing.append("tcpdump")
    
    if not Path("/var/lib/ieee-data/oui.txt").exists():
        sys_missing.append("ieee-data")

    if sys_missing:
        print(f"[install] Missing system packages: {sys_missing}. Installing now...")
        subprocess.run(f"apt-get update && apt-get install -y {' '.join(sys_missing)}", shell=True)
    
    pip_missing = []
    try:
        import scapy
    except ImportError: pip_missing.append("scapy")
    
    try:
        import flask
    except ImportError: pip_missing.append("flask")
    
    try:
        import requests
    except ImportError: pip_missing.append("requests")

    if pip_missing:
        print(f"[install] Missing python packages: {pip_missing}. Installing now...")
        subprocess.run([sys.executable, "-m", "pip", "install", *pip_missing, "--break-system-packages"])

ensure_dependencies()

LOG_DIR        = Path.home() / "radar_logs"
_ts            = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
PCAP_PATH      = LOG_DIR / f"capture_{_ts}.pcap"
CSV_PATH       = LOG_DIR / f"detections_{_ts}.csv"
JSON_PATH      = LOG_DIR / f"detections_{_ts}.json"
CLUSTER_JSON   = LOG_DIR / "radar_clusters.json"
ERROR_LOG_PATH = LOG_DIR / f"errors_{_ts}.log"
STATE_PATH     = LOG_DIR / "single_state.pid"

CLUSTER_DUMP_INTERVAL = 10  # seconds

DASHBOARD_PORT = 8080

# Channel hopping (2.4GHz 1–14 + 5GHz common channels)
HOP_CHANNELS_24 = list(range(1, 15))
HOP_CHANNELS_5  = [36, 40, 44, 48, 52, 56, 60, 64,
                   100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
                   149, 153, 157, 161, 165]
HOP_CHANNELS    = HOP_CHANNELS_24 + HOP_CHANNELS_5
HOP_INTERVAL    = 0.25                 # seconds per channel

# ---------- DIRECTORY SETUP ----------
def ensure_dirs():
    """Ensure the log directory exists and is writable."""
    try:
        if not LOG_DIR.exists():
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            # If we're root, make sure the directory is accessible
            if os.geteuid() == 0:
                os.chmod(LOG_DIR, 0o777)
    except Exception as e:
        print(f"Error creating log directory {LOG_DIR}: {e}")

# ---------- LOGGING ----------
def setup_logger(name, log_file, level=logging.INFO):
    """Utility to create structured loggers."""
    ensure_dirs()
    handler = logging.FileHandler(log_file)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(threadName)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    # Add console handler only for the main logger
    if name == "wifi_radar":
        ch = logging.StreamHandler()
        ch.setLevel(logging.ERROR)
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(ch)
    return logger

# Global loggers
_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
ensure_dirs()
log = setup_logger("wifi_radar", LOG_DIR / f"system_{_ts}.log")
sniff_log = setup_logger("sniff", LOG_DIR / f"sniff_{_ts}.log", level=logging.DEBUG)
error_log = setup_logger("error", LOG_DIR / f"error_{_ts}.log", level=logging.DEBUG)

# ---------- GLOBAL SHUTDOWN FLAG ----------
_shutdown = threading.Event()

# ---------- SHELL HELPERS ----------
def run(cmd, check=True, capture=False, quiet=False):
    if not quiet:
        print(f"[cmd] {cmd}")
    if capture:
        return subprocess.run(cmd, shell=True, check=check,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return subprocess.run(cmd, shell=True, check=check)

def require_root():
    if getpass.getuser() != "root":
        print("ERROR: run as root (sudo).")
        sys.exit(1)

def iface_info(iface):
    typ = None; st = None
    out = run(f"iw dev {iface} info", check=False, capture=True).stdout
    for ln in out.splitlines():
        ln = ln.strip()
        if ln.startswith("type"):
            typ = ln.split()[-1]; break
    out2 = run(f"ip link show {iface}", check=False, capture=True).stdout
    if "<" in out2 and ">" in out2:
        flags = out2.split("<",1)[1].split(">",1)[0]
        st = "UP" if "UP" in flags.split(",") else "DOWN"
    return {"type": typ or "unknown", "state": st or "DOWN"}

def set_type(iface, newtype):
    run(f"ip link set {iface} down", check=False)
    run(f"iw dev {iface} set type {newtype}", check=False)
    run(f"ip link set {iface} up", check=False)

def set_updown(iface, up=True):
    run(f"ip link set {iface} {'up' if up else 'down'}", check=False)

# ---------- OUI / Vendor (Wireshark text manuf) ----------
MANUF_FILE = Path("/var/lib/ieee-data/oui.txt")

class OuiLookup:
    """
    Parses /var/lib/ieee-data/oui.txt (IEEE format).
    Keeps a longest-prefix map so we prefer 6-byte over 3-byte hits.
    """
    def __init__(self, manuf_path: Path):
        self.path = Path(manuf_path)
        self.map = {}
        if self.path.exists():
            try:
                self._load()
            except Exception as e:
                print(f"[oui] warn: {e}")
        else:
            print("[oui] Error: /var/lib/ieee-data/oui.txt not found. Vendors will show [Unknown]")

    @staticmethod
    def _clean_hex(s: str) -> str:
        s = s.strip().lower().replace('-',':').replace('.',':')
        parts = [p for p in s.split(':') if p]
        return ':'.join(parts)

    def _load(self):
        with self.path.open(encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.split("(hex)", 1)
                    if len(parts) == 2:
                        prefix = self._clean_hex(parts[0].strip())
                        vendor = parts[1].strip()
                        self.map[prefix] = vendor

    def vendor(self, mac: str) -> str:
        if not self.map or not mac:
            return "[Unknown]"
        m = self._clean_hex(mac)
        parts = m.split(':')
        while len(parts) < 6:
            parts.append('00')
        candidates = [
            ':'.join(parts[:6]),
            ':'.join(parts[:5]),
            ':'.join(parts[:4]),
            ':'.join(parts[:3]),
        ]
        for c in candidates:
            if c in self.map:
                return self.map[c]
        return "[Unknown]"

OUI = OuiLookup(MANUF_FILE)

# ---------- CAPTURE ----------
def start_pcap(iface, path):
    return subprocess.Popen(["tcpdump", "-i", iface, "-w", str(path)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ---------- CHANNEL HOPPER ----------
# Export current channel for the dashboard
_current_channel = "?"
_auto_lock_channel = None

def get_current_channel():
    return _current_channel

def channel_hopper(iface):
    """Cycle through 2.4GHz + 5GHz Wi-Fi channels until shutdown is signalled."""
    global _current_channel, _auto_lock_channel
    try:
        idx = 0
        fail_count = {}
        while not _shutdown.is_set():
            if _auto_lock_channel:
                ch = _auto_lock_channel
                run(f"iw dev {iface} set channel {ch}", check=False, capture=True, quiet=True)
                _current_channel = str(ch)
                _shutdown.wait(1.0)
                continue

            ch = HOP_CHANNELS[idx % len(HOP_CHANNELS)]
            result = run(f"iw dev {iface} set channel {ch}", check=False, capture=True, quiet=True)
            if result.returncode != 0:
                fail_count[ch] = fail_count.get(ch, 0) + 1
                if fail_count[ch] == 1:
                    log.warning(f"Channel {ch} not supported by {iface}, skipping")
            else:
                _current_channel = str(ch)
            idx += 1
            _shutdown.wait(HOP_INTERVAL)
    except Exception:
        log.error(f"Channel hopper crashed:\n{traceback.format_exc()}")
    print("[hopper] stopped.")

# ---------- CLUSTER DUMP THREAD ----------
def cluster_dump_thread(cluster_engine):
    """Periodically serialise cluster data to radar_clusters.json."""
    try:
        while not _shutdown.is_set():
            _shutdown.wait(CLUSTER_DUMP_INTERVAL)
            if _shutdown.is_set():
                break
            try:
                cluster_engine.dump_json(str(CLUSTER_JSON))
            except Exception:
                log.error(f"Cluster dump error:\n{traceback.format_exc()}")
    except Exception:
        log.error(f"Cluster dump thread crashed:\n{traceback.format_exc()}")
    # Final dump on exit
    try:
        cluster_engine.dump_json(str(CLUSTER_JSON))
    except Exception:
        pass
    print("[cluster_dump] stopped.")

# ---------- DETECTOR ----------
def start_detector(iface, target_mac, ssid_filter, csv_path, json_path,
                   cluster_engine=None, session_engine=None):
    """Clients-only mgmt frames -> stats for HUD + fingerprint/cluster/session."""
    CLIENT_OK = {
        (0,0):"AssocReq",
        (0,2):"ReassocReq",
        (0,4):"ProbeReq",
        (0,10):"Disassoc",
        (0,11):"Auth",
        (0,12):"Deauth",
    }

    target  = (target_mac or "").lower().strip()
    ssidflt = (ssid_filter or "").strip()

    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline="") as f:
            csv.writer(f).writerow(["timestamp","mac","rssi","type","ssid","vendor","channel"])

    # JSONL file extension swap inline if we were passed a .json path
    jsonl_path = Path(json_path).with_suffix('.jsonl')

    counts = {
        "total":0, "by_type":{}, "by_ssid":{}, "by_mac":{},
        "probes_directed":0, "probes_broadcast":0,
        "closest": {"mac":"", "rssi":-999, "ssid":"", "vendor":"[Unknown]"}
    }
    last_hits = []
    # Dictionary to store last seen timestamp for deduplication: {(mac, ssid, type): last_seen_float}
    seen_time = {}

    def rssi(pkt):
        try:
            return pkt.dBm_AntSignal
        except AttributeError:
            return None

    def get_channel(pkt):
        try:
            return pkt.ChannelFrequency
        except AttributeError:
            return None

    def freq_to_chan(freq):
        if freq is None: return "?"
        if 2412 <= freq <= 2484:
            if freq == 2484: return 14
            return (freq - 2407) // 5
        # 5GHz channels
        if 5170 <= freq <= 5825:
            return (freq - 5000) // 5
        return "?"

    def get_ssid(pkt):
        """Extract SSID from Dot11Elt layer (ID=0)."""
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                try:
                    return elt.info.decode(errors="ignore")
                except Exception:
                    return ""
            elt = elt.payload.getlayer(Dot11Elt)
        return ""

    def want(pkt):
        if not pkt.haslayer(Dot11): return False
        key = (pkt.type, pkt.subtype)
        if key not in CLIENT_OK: return False
        if target:
            macs = [pkt.addr1, pkt.addr2, pkt.addr3]
            if not any(m and m.lower()==target for m in macs): return False
        if ssidflt:
            if get_ssid(pkt).strip().lower() != ssidflt.lower():
                return False
        return True

    def handle(pkt):
        try:
            _handle_inner(pkt)
        except Exception:
            log.error(f"Packet handler error:\n{traceback.format_exc()}")

    def _handle_inner(pkt):
        global _auto_lock_channel
        if _shutdown.is_set(): return
        if not want(pkt): return
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        subtype = (pkt.type, pkt.subtype)
        kind = CLIENT_OK[subtype]
        ssid = get_ssid(pkt)
        mac  = (pkt.addr2 or pkt.addr1 or pkt.addr3 or "").lower()
        sig = rssi(pkt)
        sig_str = str(sig) if sig is not None else "?"
        chan = freq_to_chan(get_channel(pkt))

        # Auto-lock onto channel if this is a targeted Fox Hunt
        if ssidflt and not _auto_lock_channel and isinstance(chan, int):
            _auto_lock_channel = chan
            print(f"\n[foxhunt] Target '{ssid}' intercepted! Auto-locking hopper to channel {chan}!")

        # probe counters
        if subtype == (0,4):
            if ssid: counts["probes_directed"] += 1
            else:    counts["probes_broadcast"] += 1

        # stats
        counts["total"] += 1
        counts["by_type"][kind] = counts["by_type"].get(kind,0)+1
        if ssid:
            counts["by_ssid"][ssid] = counts["by_ssid"].get(ssid,0)+1

        vendor_str = "[Unknown]"
        if mac:
            m = counts["by_mac"].get(mac, {"hits":0})
            m["hits"] += 1
            if ssid: m["last_ssid"] = ssid
            m["last_rssi"] = sig if sig is not None else ""
            if "vendor" not in m:
                m["vendor"] = OUI.vendor(mac)
            vendor_str = m.get("vendor","[Unknown]")
            counts["by_mac"][mac] = m

            # closest tracker
            if sig is not None and sig > counts["closest"]["rssi"]:
                counts["closest"] = {
                    "mac": mac, "rssi": sig,
                    "ssid": ssid or "-",
                    "vendor": vendor_str
                }

        # --- CSV + JSONL logging (time-based deduplication) ---
        csv_key = (mac, ssid, kind)
        now_ts = time.time()
        # Log if we haven't seen this specific (mac, ssid, type) tuple in the last 10 seconds
        if csv_key not in seen_time or (now_ts - seen_time[csv_key]) > 10.0:
            seen_time[csv_key] = now_ts
            with open(csv_path, "a", newline="") as f:
                csv.writer(f).writerow([ts, mac, sig_str, kind, ssid, vendor_str, chan])
            # Append atomic line to JSONL
            entry = {"timestamp": ts, "mac": mac, "rssi": sig_str, "type": kind,
                     "ssid": ssid, "vendor": vendor_str, "channel": str(chan)}
            with open(jsonl_path, "a") as f:
                f.write(json.dumps(entry) + "\n")

        # --- Behavioral fingerprinting & clustering ---
        if cluster_engine is not None:
            try:
                fp = build_ie_fingerprint(pkt)
                if fp is not None:
                    now_ts = time.time()
                    rssi_val = sig if sig is not None else None

                    # Session assignment
                    sess_id = None
                    if session_engine is not None:
                        sess_id = session_engine.assign_session(
                            mac, now_ts, fingerprint_hash=fp.full_fingerprint_hash
                        )

                    # Cluster update
                    cluster = cluster_engine.update(
                        fingerprint_hash=fp.full_fingerprint_hash,
                        mac=mac,
                        ssid=ssid or None,
                        rssi=rssi_val,
                        session_id=sess_id,
                    )

                    # Recompute confidence
                    cluster.confidence_score = compute_confidence(cluster.to_dict())
                    sniff_log.debug(f"[cluster] Updated cluster {cluster.cluster_id} for {mac} (sid={sess_id})")
                else:
                    # Debug: why was fingerprint None?
                    # build_ie_fingerprint returns None if no Dot11Elt
                    if not pkt.haslayer(Dot11Elt):
                        sniff_log.debug(f"[sniff] No Dot11Elt in {kind} from {mac}")
                    else:
                        sniff_log.debug(f"[sniff] Failed to build fingerprint for {kind} from {mac}")
            except Exception:
                error_log.error(f"Fingerprint/cluster error:\n{traceback.format_exc()}")

        # Note: HUD queue logic was removed as the web dashboard reads from files/engines directly.

    # BPF filter: only management frames (type 0)
    # "type mgt" isn't supported on all systems, so fall back to no filter
    try:
        sniff(iface=iface, prn=handle, store=False,
              filter="wlan type mgt",
              stop_filter=lambda _: _shutdown.is_set())
    except Scapy_Exception:
        # BPF compile failed – retry without filter (handler already
        # checks for Dot11 management frames, so this is safe)
        print("[sniff] BPF 'type mgt' not supported, restarting without BPF filter…")
        try:
            sniff(iface=iface, prn=handle, store=False,
                  stop_filter=lambda _: _shutdown.is_set())
        except Exception:
            log.error(f"Detector sniff crashed:\n{traceback.format_exc()}")
    except Exception:
        log.error(f"Detector sniff crashed:\n{traceback.format_exc()}")
    print("[detector] stopped.")

# ---------- HUD ----------


# ---------- START / STOP ----------
def _signal_handler(signum, frame):
    """Gracefully shut down all threads on SIGINT/SIGTERM."""
    print(f"\n[signal] Received signal {signum}, shutting down…")
    _shutdown.set()

def start_flow(target_channel=None):
    print("=== Wi-Fi Radar START ===")
    ensure_dirs()

    # Register graceful signal handlers
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Verify the Alfa adapter exists before proceeding
    check = run(f"ip link show {ALFA_IFACE}", check=False, capture=True, quiet=True)
    if check.returncode != 0:
        print(f"ERROR: Adapter '{ALFA_IFACE}' not found.")
        print("       Is the Alfa adapter plugged in?")
        print("       Check available interfaces with: ip link show")
        sys.exit(1)

    snap = iface_info(ALFA_IFACE)
    print(f"[snapshot] {ALFA_IFACE}: {snap}")

    if run("which airmon-ng", check=False, capture=True, quiet=True).returncode == 0:
        print("[airmon-ng] Skipping check kill to preserve NetworkManager...")
        # run("airmon-ng check kill", check=False)

    if run("which nmcli", check=False, capture=True, quiet=True).returncode == 0:
        print("[nmcli] unmanaging Alfa; leaving onboard managed")
        run(f"nmcli device set {ALFA_IFACE} managed no", check=False)
        print("[nmcli] waiting 2 seconds for NM to detach...")
        time.sleep(2)

    set_updown(ALFA_IFACE, False)
    time.sleep(0.5)
    run(f"iw dev {ALFA_IFACE} set type monitor")
    time.sleep(0.5)
    set_updown(ALFA_IFACE, True)
    time.sleep(1)

    check_tcpdump = run("which tcpdump", check=False, capture=True, quiet=True)
    if check_tcpdump.returncode != 0:
        print("ERROR: 'tcpdump' is missing. Install via your package manager (e.g., sudo apt install tcpdump)")
        stop_flow(snapshot=snap, pcap_proc=None)
        sys.exit(1)

    pcap_proc = start_pcap(ALFA_IFACE, PCAP_PATH)

    target_mac = ""
    ssid_filter= input("Filter by Target SSID (blank=ANY): ").strip()

    # --- Initialize fingerprinting / clustering / session engines ---
    clust_engine = DeviceClusterEngine()
    sess_engine  = SessionEngine()
    print("[engines] Fingerprint + Cluster + Session engines initialized.")

    # Start channel hopper thread OR lock channel
    global _current_channel
    if target_channel:
        print(f"[hop] Locking adapter to channel: {target_channel} (Targeted Fox Hunt)")
        run(f"iw dev {ALFA_IFACE} set channel {target_channel}", check=False)
        _current_channel = str(target_channel)
    else:
        hop_thr = threading.Thread(target=channel_hopper, args=(ALFA_IFACE,), daemon=True)
        hop_thr.start()

    # Start detector thread
    det_thr = threading.Thread(target=start_detector,
                               args=(ALFA_IFACE, target_mac, ssid_filter, CSV_PATH, JSON_PATH),
                               kwargs={"cluster_engine": clust_engine, "session_engine": sess_engine},
                               daemon=True)
    det_thr.start()

    # Start periodic cluster dump thread
    dump_thr = threading.Thread(target=cluster_dump_thread, args=(clust_engine,), daemon=True)
    dump_thr.start()

    dashboard_url = f"http://localhost:{DASHBOARD_PORT}"

    print("\n[RUNNING]")
    print(f"  Monitor iface : {ALFA_IFACE} (monitor mode)")
    print(f"  Onboard iface : {ONBOARD_IFACE} (left alone; keep your internet)")
    if target_channel:
        print(f"  Target Channel: {target_channel} (LOCKED)")
    else:
        print(f"  Channel hop   : ch {HOP_CHANNELS[0]}–{HOP_CHANNELS[-1]} ({len(HOP_CHANNELS_24)} x 2.4GHz + {len(HOP_CHANNELS_5)} x 5GHz) every {HOP_INTERVAL}s")
    print(f"  PCAP          : {PCAP_PATH}")
    print(f"  CSV           : {CSV_PATH}")
    print(f"  JSON          : {JSON_PATH}")
    print(f"  Clusters      : {CLUSTER_JSON}")
    print(f"  Error log     : {ERROR_LOG_PATH}")
    print(f"  Dashboard     : {dashboard_url}")
    if target_mac: print(f"  MAC filter    : {target_mac}")
    if ssid_filter: print(f"  SSID filter   : {ssid_filter}")
    print("  Press Ctrl+C or run: sudo python3 wifi_radar.py stop")

    # Start live web dashboard thread
    dash_thr = threading.Thread(
        target=start_dashboard,
        args=(clust_engine, sess_engine, str(LOG_DIR)),
        kwargs={"port": DASHBOARD_PORT, "shutdown_event": _shutdown, "get_channel_cb": get_current_channel},
        daemon=True,
    )
    dash_thr.start()

    # Auto-open dashboard in the default browser
    time.sleep(0.5)  # let the server bind first
    try:
        webbrowser.open(dashboard_url)
        print(f"[browser] Opened {dashboard_url}")
    except Exception:
        print(f"[browser] Could not auto-open browser. Navigate to {dashboard_url} manually.")

    STATE_PATH.write_text(str(pcap_proc.pid))

    try:
        while not _shutdown.is_set():
            _shutdown.wait(2)
    except KeyboardInterrupt:
        _shutdown.set()
    finally:
        stop_flow(snapshot=snap, pcap_proc=pcap_proc)

def stop_flow(snapshot=None, pcap_proc=None):
    print("\n=== Wi-Fi Radar STOP ===")
    _shutdown.set()

    # Kill tcpdump — prefer the live process handle, fall back to PID file
    if pcap_proc is not None:
        try:
            pcap_proc.terminate()
            pcap_proc.wait(timeout=5)
            print(f"[stop] tcpdump terminated (pid={pcap_proc.pid})")
        except Exception as e:
            print(f"[stop] warn terminating tcpdump: {e}")
    elif STATE_PATH.exists():
        try:
            pid = int(STATE_PATH.read_text().strip())
            print(f"[stop] killing tcpdump pid={pid}")
            os.kill(pid, signal.SIGTERM)
        except Exception as e:
            print(f"[stop] warn: {e}")

    try: STATE_PATH.unlink()
    except Exception: pass

    snap = snapshot or iface_info(ALFA_IFACE)
    cur  = iface_info(ALFA_IFACE)
    want_type = snap.get("type") or "managed"
    want_up   = (snap.get("state") == "UP")
    if cur["type"] != want_type:
        print(f"[restore] {ALFA_IFACE} type {cur['type']} -> {want_type}")
        set_type(ALFA_IFACE, want_type)
    if (cur["state"]=="UP") != want_up:
        print(f"[restore] {ALFA_IFACE} state {cur['state']} -> {'UP' if want_up else 'DOWN'}")
        set_updown(ALFA_IFACE, want_up)

    if run("which nmcli", check=False).returncode == 0:
        run(f"nmcli device set {ALFA_IFACE} managed yes", check=False)

    print(f"[stop] PCAP at: {PCAP_PATH}")
    print(f"[stop] CSV  at: {CSV_PATH}")
    print(f"[stop] JSON at: {JSON_PATH}")
    print(f"[stop] Errors : {ERROR_LOG_PATH}")
    print("[stop] done.")

def main():
    require_root()
    ensure_dirs()
    if len(sys.argv) < 2:
        print(f"Usage:\n  sudo python3 {Path(__file__).name} start [--channel <num>]\n  sudo python3 {Path(__file__).name} stop")
        return
    cmd = sys.argv[1].lower()
    
    target_channel = None
    if "--channel" in sys.argv:
        try:
            idx = sys.argv.index("--channel")
            target_channel = int(sys.argv[idx + 1])
        except (ValueError, IndexError):
            print("ERROR: --channel requires a valid integer channel number.")
            return

    try:
        if cmd == "start":
            start_flow(target_channel=target_channel)
        elif cmd == "stop":
            stop_flow()
        else:
            print("Unknown command. Use start/stop.")
    except Exception:
        log.critical(f"Fatal error in main:\n{traceback.format_exc()}")
        raise

if __name__ == "__main__":
    main()
