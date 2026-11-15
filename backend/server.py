#!/usr/bin/env python3
"""Kiro Event Viewer backend: a late-90s style event log for Kiro Crew.

Three logs, the way the classic workstation event viewer had them:

* ``system``      Kiro Crew's own notifications (``~/.kiro/crew/notifications.jsonl``)
* ``security``    Kiro Crew's security audit log (``~/.kiro/crew/security_events.jsonl``)
* ``application`` events any of your own services post (this app's data dir)

Both Kiro Crew logs are read-only here; this app never writes to them.

How a service posts an event (``application`` log):

1. Drop a JSON-lines file into ``<data>/inbox/`` (owner-only directory). Each line
   is one event: ``{"source": "...", "level": "warning", "message": "..."}``.
   ``tools/kiro-event`` writes one atomically for you.
2. Or POST the same JSON to ``/api/apps/kiro-event-viewer/events`` through the
   Kiro Crew gateway, which authenticates the caller.

Security: binds 127.0.0.1 only. Every route except ``/health`` requires the
gateway's signed ``X-KiroCrew-Proxy-V2`` header (HMAC with the per-app secret in
``KIROCREW_PROXY_SECRET``, a fresh timestamp and a single-use nonce), so another
local process cannot skip the gateway's auth by calling this port directly.
With no secret configured every signed route refuses (fail closed).

Stdlib only; Python 3.9+.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

APP = "kiro-event-viewer"
PREFIX = f"/api/apps/{APP}"
BIND_HOST = "127.0.0.1"  # loopback only; the gateway proxies to this port
PORT = int(os.environ.get("PORT", "9100"))

APP_ROOT = Path(__file__).resolve().parents[1]


def _crew_home() -> Path:
    env = os.environ.get("KIROCREW_HOME")
    if env:
        return Path(env)
    # Installed apps live at <crew home>/apps/<name>/.
    if APP_ROOT.parent.name == "apps":
        return APP_ROOT.parent.parent
    return Path.home() / ".kiro" / "crew"


CREW_HOME = _crew_home()
DATA = Path(os.environ.get("EVENT_VIEWER_DATA") or (APP_ROOT / "data"))
INBOX = DATA / "inbox"
APP_LOG = DATA / "application.jsonl"

MAX_APP_EVENTS = 10_000      # oldest are overwritten past this, like "overwrite as needed"
KEEP_ON_TRIM = 8_000
MAX_MESSAGE = 4_000
MAX_DATA_JSON = 8_192
MAX_LINE = 16_384
MAX_INBOX_FILE = 1_048_576
MAX_BODY = 32_768
SECURITY_TAIL = 2_000
SKEW = 60

LEVELS = {
    "information": "information", "info": "information",
    "warning": "warning", "warn": "warning",
    "error": "error", "err": "error",
    "success": "success_audit", "success_audit": "success_audit",
    "failure": "failure_audit", "failure_audit": "failure_audit",
}
SEC_OK = {"completed", "granted", "ok", "allowed", "invoked", "success", "accepted",
          "refined", "enabled", "started", "staged", "auto"}
SEC_FAIL = {"failed", "failure", "error", "denied", "expired", "sigterm"}
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_NONCE = re.compile(r"^[0-9a-f]{32}$")


# ── gateway proxy signature (v2, replay-proof) ─────────────────────────────

class ReplayCache:
    def __init__(self, max_entries: int = 4096) -> None:
        self._seen: dict[str, float] = {}
        self._max = max_entries
        self._lock = threading.Lock()

    def accept(self, nonce: str, expires_at: float, now: float) -> bool:
        with self._lock:
            for k in [k for k, exp in self._seen.items() if exp < now]:
                del self._seen[k]
            if nonce in self._seen or len(self._seen) >= self._max:
                return False
            self._seen[nonce] = expires_at
            return True


REPLAY = ReplayCache()


def verify_signature(header: str, nonce: str, method: str, target: str, body: bytes,
                     secret: str | None = None, now: float | None = None) -> bool:
    key = os.environ.get("KIROCREW_PROXY_SECRET", "") if secret is None else secret
    if not key or not header or not nonce or not _NONCE.match(nonce):
        return False
    ts_str, _, sig = header.partition(":")
    if not (ts_str.isascii() and ts_str.isdigit()) or len(ts_str) > 12 or not sig:
        return False
    ts = int(ts_str)
    clock = time.time() if now is None else now
    if not clock - SKEW <= ts <= clock + SKEW:
        return False
    msg = f"v2:{ts_str}:{nonce}:{method}:{target}:{hashlib.sha256(body or b'').hexdigest()}"
    expected = hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected.encode("utf-8", "surrogatepass"),
                               sig.encode("utf-8", "surrogatepass")):
        return False
    return REPLAY.accept(nonce, ts + SKEW, clock)


# ── helpers ─────────────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_ts(value) -> str | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value)
        if v > 1e12:  # milliseconds
            v /= 1000
        try:
            return datetime.fromtimestamp(v, timezone.utc).isoformat(timespec="seconds")
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value.strip():
        s = value.strip().replace("Z", "+00:00")
        try:
            d = datetime.fromisoformat(s)
        except ValueError:
            return None
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc).isoformat(timespec="seconds")
    return None


def clean(text, limit: int) -> str:
    return _CTRL.sub("", str(text or "")).strip()[:limit]


def normalize(raw, via: str) -> dict | None:
    """Validate one posted event; None if it is not usable."""
    if not isinstance(raw, dict):
        return None
    source = clean(raw.get("source"), 64)
    message = clean(raw.get("message"), MAX_MESSAGE)
    if not source or not message:
        return None
    level = LEVELS.get(str(raw.get("level", "information")).strip().lower(), "information")
    event_id = raw.get("event_id")
    if not (isinstance(event_id, int) and not isinstance(event_id, bool) and 0 <= event_id <= 65535):
        event_id = 0
    data = raw.get("data")
    if not isinstance(data, (dict, list)):
        data = None
    elif len(json.dumps(data, default=str)) > MAX_DATA_JSON:
        data = {"note": f"data dropped: larger than {MAX_DATA_JSON} bytes"}
    return {
        "level": level,
        "ts": parse_ts(raw.get("ts")) or now_iso(),
        "source": source,
        "category": clean(raw.get("category"), 64),
        "event_id": event_id,
        "message": message,
        "data": data,
        "via": via,
    }


# ── application log store ───────────────────────────────────────────────────

class AppLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()
        self.next_id = 1
        self.count = 0
        if path.exists():
            last = None
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    self.count += 1
                    last = line
            if last:
                try:
                    self.next_id = int(json.loads(last).get("id", 0)) + 1
                except (ValueError, TypeError, json.JSONDecodeError):
                    pass

    def append(self, events: list[dict]) -> list[int]:
        ids = []
        with self.lock:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                for ev in events:
                    ev = {"id": self.next_id, "ingested_at": now_iso(), **ev}
                    fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
                    ids.append(self.next_id)
                    self.next_id += 1
                    self.count += 1
            if self.count > MAX_APP_EVENTS:
                lines = self.path.read_text(encoding="utf-8").splitlines()[-KEEP_ON_TRIM:]
                tmp = self.path.with_suffix(".tmp")
                tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
                tmp.replace(self.path)
                self.count = len(lines)
        return ids

    def read(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def clear(self) -> None:
        with self.lock:
            if self.path.exists():
                self.path.unlink()
            self.count = 0


LOG = AppLog(APP_LOG)


def ingest_inbox() -> int:
    """Move every settled inbox file into the application log."""
    if not INBOX.is_dir():
        return 0
    taken = 0
    cutoff = time.time() - 1.0
    for p in sorted(INBOX.glob("*.jsonl")):
        try:
            st = p.stat()
            if st.st_mtime > cutoff:
                continue  # still being written
            work = p.with_suffix(".processing")
            p.replace(work)
        except OSError:
            continue
        good, bad = [], 0
        try:
            if work.stat().st_size > MAX_INBOX_FILE:
                bad = -1
            else:
                for line in work.read_text(encoding="utf-8", errors="replace").splitlines():
                    if not line.strip():
                        continue
                    if len(line) > MAX_LINE:
                        bad += 1
                        continue
                    try:
                        ev = normalize(json.loads(line), via=f"inbox:{p.name}")
                    except json.JSONDecodeError:
                        ev = None
                    if ev:
                        good.append(ev)
                    else:
                        bad += 1
        finally:
            try:
                work.unlink()
            except OSError:
                pass
        if bad:
            note = (f"{p.name} was larger than {MAX_INBOX_FILE} bytes and was skipped." if bad < 0
                    else f"{bad} line(s) in {p.name} were not valid events (need source and message).")
            warn = normalize({"source": "kiro-event-viewer", "level": "warning",
                              "category": "Inbox", "message": note}, via="viewer")
            if warn:
                good.append(warn)
        if good:
            LOG.append(good)
            taken += len(good)
    return taken


def inbox_loop(stop: threading.Event) -> None:
    INBOX.mkdir(mode=0o700, parents=True, exist_ok=True)
    while not stop.is_set():
        try:
            ingest_inbox()
        except Exception as exc:  # keep the service alive; report on the next pass
            print(f"inbox error: {exc}", file=sys.stderr)
        stop.wait(2.0)


# ── Kiro Crew's own logs (read-only) ────────────────────────────────────────

def _read_jsonl(path: Path, tail: int | None = None) -> list[tuple[int, dict]]:
    if not path.exists():
        return []
    rows: deque = deque(maxlen=tail) if tail else deque()
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                rows.append((n, line))
    out = []
    for n, line in rows:
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(d, dict):
            out.append((n, d))
    return out


def system_level(title: str, body: str, kind: str) -> str:
    """Classify a notification from its title, kind and a few exact phrases.

    Never from arbitrary body words: a skill named "diagnose-...-error" is not an error.
    """
    t, b = title.lower(), body.lower()
    if "resolved" in t or "recovered" in t:
        return "information"
    if "failed" in t or "error" in t or "stopped with an error" in b:
        return "error"
    if "⚠" in title or "⛔" in b[:4] or kind.lower() == "resources" or "tight" in t or "blocked" in t:
        return "warning"
    return "information"


def system_events() -> list[dict]:
    out = []
    for n, d in _read_jsonl(CREW_HOME / "notifications.jsonl"):
        title = clean(d.get("title"), 300)
        body = clean(d.get("body"), MAX_MESSAGE)
        kind = clean(d.get("kind"), 40) or "general"
        level = system_level(title, body, kind)
        out.append({
            "id": n, "level": level, "ts": parse_ts(d.get("ts")) or "",
            "source": f"Kiro Crew ({clean(d.get('source'), 30) or 'system'})",
            "category": kind.capitalize(), "event_id": 0,
            "message": title + (f"\n\n{body}" if body else ""),
            "data": {k: d[k] for k in ("channel", "priority", "slot", "url", "tag") if d.get(k)} or None,
        })
    return out


def security_events() -> list[dict]:
    out = []
    for n, d in _read_jsonl(CREW_HOME / "security_events.jsonl", tail=SECURITY_TAIL):
        outcome = str(d.get("outcome") or "").lower()
        level = ("success_audit" if outcome in SEC_OK
                 else "failure_audit" if outcome in SEC_FAIL else "information")
        op = clean(d.get("operation"), 200)
        svc = clean(d.get("downstream_service"), 80)
        err = clean(d.get("error"), 400)
        msg = op or clean(d.get("event_type"), 60)
        if svc:
            msg += f" → {svc}"
        msg += f" ({outcome or 'no outcome'})"
        if err:
            msg += f"\n\n{err}"
        detail = {k: d.get(k) for k in ("event_id", "event_type", "operation", "outcome", "agent",
                                        "source", "downstream_service", "request_id") if d.get(k)}
        if d.get("resources"):
            detail["resources"] = clean(json.dumps(d.get("resources"), default=str), 500)
        out.append({
            "id": n, "level": level, "ts": parse_ts(d.get("timestamp")) or "",
            "source": clean(d.get("source"), 40) or "Kiro Crew",
            "category": clean(d.get("event_type"), 40).replace("_", " ").title(),
            "event_id": 0, "message": msg, "data": detail or None,
        })
    return out


READERS = {"application": LOG.read, "system": system_events, "security": security_events}


def query(log: str, params: dict) -> dict:
    events = READERS[log]()
    total = len(events)
    level = params.get("level", [""])[0]
    if level:
        wanted = {LEVELS.get(x.strip().lower(), x.strip().lower()) for x in level.split(",")}
        events = [e for e in events if e.get("level") in wanted]
    q = params.get("q", [""])[0].strip().lower()
    if q:
        events = [e for e in events if q in f"{e.get('source','')} {e.get('category','')} {e.get('message','')}".lower()]
    src = params.get("source", [""])[0].strip().lower()
    if src:
        events = [e for e in events if src == str(e.get("source", "")).lower()]
    events.sort(key=lambda e: (e.get("ts") or "", e.get("id", 0)), reverse=True)
    try:
        limit = max(1, min(1000, int(params.get("limit", ["300"])[0])))
    except ValueError:
        limit = 300
    return {"log": log, "total": total, "matched": len(events), "events": events[:limit]}


# ── HTTP ────────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "KiroEventViewer/0.1"

    def _send(self, code: int, data) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> bytes | None:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if n < 0 or n > MAX_BODY:
            return None
        return self.rfile.read(n) if n else b""

    def _authorized(self, body: bytes) -> bool:
        return verify_signature(self.headers.get("X-KiroCrew-Proxy-V2", ""),
                                self.headers.get("X-KiroCrew-Proxy-Nonce", ""),
                                self.command, self.path, body)

    def _route(self) -> None:
        url = urlsplit(self.path)
        if self.command == "GET" and url.path == "/health":
            return self._send(200, {"status": "ok", "app": APP})
        body = self._body()
        if body is None:
            return self._send(413, {"error": "request body too large"})
        if not self._authorized(body):
            return self._send(401, {"error": "unauthorized: requests must come through the Kiro Crew gateway"})
        params = parse_qs(url.query)
        path = url.path
        if self.command == "GET" and path == f"{PREFIX}/logs":
            return self._send(200, {
                "computer": os.uname().nodename.split(".")[0].upper() if hasattr(os, "uname") else "LOCAL",
                "logs": [{"name": k, "count": len(v())} for k, v in READERS.items()],
                "inbox": str(INBOX),
            })
        if self.command == "GET" and path == f"{PREFIX}/events":
            log = params.get("log", ["application"])[0]
            if log not in READERS:
                return self._send(400, {"error": f"unknown log {log!r}"})
            return self._send(200, query(log, params))
        if self.command == "POST" and path == f"{PREFIX}/events":
            try:
                raw = json.loads(body or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "body must be JSON"})
            items = raw if isinstance(raw, list) else [raw]
            if len(items) > 100:
                return self._send(400, {"error": "at most 100 events per request"})
            evs = [e for e in (normalize(x, via="api") for x in items) if e is not None]
            if not evs or len(evs) != len(items):
                return self._send(400, {"error": "each event needs a non-empty source and message"})
            return self._send(201, {"ids": LOG.append(evs)})
        if self.command == "DELETE" and path == f"{PREFIX}/events":
            if params.get("log", [""])[0] != "application":
                return self._send(400, {"error": "only the application log can be cleared"})
            LOG.clear()
            return self._send(200, {"cleared": "application"})
        return self._send(404, {"error": "not found"})

    do_GET = do_POST = do_DELETE = _route

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - base-class signature
        pass


class Server(ThreadingHTTPServer):
    allow_reuse_address = not sys.platform.startswith("win")
    daemon_threads = True


def main() -> None:
    DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
    stop = threading.Event()
    threading.Thread(target=inbox_loop, args=(stop,), daemon=True).start()
    if not os.environ.get("KIROCREW_PROXY_SECRET"):
        print("warning: KIROCREW_PROXY_SECRET is not set; every signed route will refuse", file=sys.stderr)
    print(f"{APP} backend on {BIND_HOST}:{PORT} (data {DATA})")
    try:
        Server((BIND_HOST, PORT), Handler).serve_forever()
    finally:
        stop.set()


if __name__ == "__main__":
    main()
