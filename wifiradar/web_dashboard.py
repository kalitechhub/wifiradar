"""
web_dashboard.py — Live web dashboard for Wi-Fi Radar on localhost:8080.

Reads cluster, session, and detection data from the engines in memory
and serves a single-page live dashboard with auto-refreshing API endpoints.

The dashboard UI is a pre-built React SPA located in wifiradar/static/.
Build it with:  npm run build:radar   (or bash wifiradar/build_radar.sh)

Usage (standalone — normally started by wifi_radar.py):
    from wifiradar.web_dashboard import start_dashboard
    start_dashboard(cluster_engine, session_engine, log_dir, port=8080)
"""

from __future__ import annotations

import json
import mimetypes
import os
import threading
import time
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional

# ---------------------------------------------------------------------------
# Module-level refs (set by start_dashboard before server starts)
# ---------------------------------------------------------------------------
_cluster_engine = None
_session_engine = None
_log_dir: Optional[Path] = None
_shutdown: Optional[threading.Event] = None
_start_time: float = time.time()

# Static files directory (built React SPA)
_STATIC_DIR = Path(__file__).parent / "static"


def _read_jsonl_file(path: str) -> list:
    """Read the last ~200 lines from a JSONL file."""
    lines = []
    try:
        # For simplicity, read all and slice the end. A huge file might want a tail-seek.
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        lines.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception:
        pass
    return lines


class DashboardHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler — serves the built React SPA + JSON API."""

    def log_message(self, fmt, *args):
        pass  # silence default stderr logging

    def _headers(self, content_type="application/json", code=200):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

    def _json(self, data, code=200):
        self._headers("application/json", code)
        self.wfile.write(json.dumps(data, default=str).encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        # --- API routes ---
        if path == "/api/clusters":
            self._api_clusters()
        elif path == "/api/sessions":
            self._api_sessions()
        elif path == "/api/detections":
            self._api_detections()
        elif path == "/api/stats":
            self._api_stats()
        # --- Static file serving ---
        else:
            self._serve_static(path)

    def _serve_static(self, path: str):
        """Serve built React SPA files from wifiradar/static/."""
        # Map / and /dashboard to index.html
        if path in ("/", "/dashboard"):
            file_path = _STATIC_DIR / "src" / "radar.html"
            if not file_path.exists():
                # Try root index.html (some builds place it there)
                file_path = _STATIC_DIR / "index.html"
        else:
            # Strip leading / and resolve relative to static dir
            rel = path.lstrip("/")
            file_path = _STATIC_DIR / rel

        # Security: prevent path traversal
        try:
            file_path = file_path.resolve()
            static_resolved = _STATIC_DIR.resolve()
            if not str(file_path).startswith(str(static_resolved)):
                self._headers("text/plain", 403)
                self.wfile.write(b"Forbidden")
                return
        except Exception:
            self._headers("text/plain", 400)
            self.wfile.write(b"Bad Request")
            return

        if file_path.exists() and file_path.is_file():
            content_type, _ = mimetypes.guess_type(str(file_path))
            content_type = content_type or "application/octet-stream"
            self._headers(content_type)
            self.wfile.write(file_path.read_bytes())
        else:
            # SPA fallback: serve index.html for unknown routes
            index = _STATIC_DIR / "src" / "radar.html"
            if not index.exists():
                index = _STATIC_DIR / "index.html"
            if index.exists():
                self._headers("text/html")
                self.wfile.write(index.read_bytes())
            else:
                # Fallback to legacy template
                tpl = Path(__file__).parent / "templates" / "radar_dashboard.html"
                if tpl.exists():
                    self._headers("text/html")
                    self.wfile.write(tpl.read_bytes())
                else:
                    self._headers("text/html", 404)
                    self.wfile.write(
                        b"<h1>Dashboard not built</h1>"
                        b"<p>Run <code>npm run build:radar</code> first.</p>"
                    )

    def _api_clusters(self):
        if _cluster_engine:
            self._json({"clusters": _cluster_engine.snapshot()})
        else:
            self._json({"clusters": []})

    def _api_sessions(self):
        if _session_engine:
            self._json({"sessions": _session_engine.all_sessions()})
        else:
            self._json({"sessions": []})

    def _api_detections(self):
        # Find the most recent JSONL in log_dir
        if _log_dir and _log_dir.exists():
            jsonls = sorted(_log_dir.glob("detections_*.jsonl"), reverse=True)
            if jsonls:
                data = _read_jsonl_file(str(jsonls[0]))
                self._json({"detections": data[-200:]})  # last 200
                return
        self._json({"detections": []})

    def _api_stats(self):
        clusters = _cluster_engine.snapshot() if _cluster_engine else []
        sessions = _session_engine.all_sessions() if _session_engine else []
        total_macs = set()
        total_ssids = set()
        total_hits = 0
        high_conf = 0
        for c in clusters:
            total_macs.update(c.get("observed_macs", []))
            total_ssids.update(c.get("seen_ssids", []))
            total_hits += c.get("hit_count", 0)
            if c.get("confidence_score", 0) >= 60:
                high_conf += 1

        uptime = int(time.time() - _start_time)
        active_chan = "?"
        if _get_channel_cb:
            try:
                active_chan = _get_channel_cb()
            except:
                pass
        
        self._json({
            "total_clusters": len(clusters),
            "total_sessions": len(sessions),
            "unique_macs": len(total_macs),
            "unique_ssids": len(total_ssids),
            "total_hits": total_hits,
            "high_confidence_clusters": high_conf,
            "uptime_seconds": uptime,
            "current_channel": active_chan
        })


class _StoppableServer(HTTPServer):
    def __init__(self, *args, shutdown_event=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._shutdown_event = shutdown_event

    def service_actions(self):
        if self._shutdown_event and self._shutdown_event.is_set():
            raise KeyboardInterrupt


def start_dashboard(
    cluster_engine,
    session_engine,
    log_dir,
    port: int = 8080,
    shutdown_event: threading.Event | None = None,
    get_channel_cb = None,
):
    """
    Start the dashboard HTTP server (blocking). Call from a daemon thread.
    """
    global _cluster_engine, _session_engine, _log_dir, _shutdown, _start_time, _get_channel_cb

    _cluster_engine = cluster_engine
    _session_engine = session_engine
    _log_dir = Path(log_dir) if log_dir else None
    _shutdown = shutdown_event
    _start_time = time.time()
    _get_channel_cb = get_channel_cb

    server = _StoppableServer(
        ("0.0.0.0", port),
        DashboardHandler,
        shutdown_event=shutdown_event,
    )
    server.timeout = 1.0
    print(f"[dashboard] Live dashboard at http://localhost:{port}")
    try:
        while not (shutdown_event and shutdown_event.is_set()):
            server.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    print("[dashboard] stopped.")
