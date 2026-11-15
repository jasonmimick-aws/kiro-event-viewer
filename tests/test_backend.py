"""Tests for the Kiro Event Viewer backend. Stdlib only:

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET = "test-secret-" + secrets.token_hex(8)
TMP = Path(tempfile.mkdtemp(prefix="kev-test-"))
HOME = TMP / "crew"
DATA = TMP / "data"
HOME.mkdir()
(HOME / "notifications.jsonl").write_text("\n".join(json.dumps(x) for x in [
    {"ts": "2026-11-13T10:00:00Z", "kind": "agent", "source": "system", "title": "⚠️ A chat stopped", "body": "Session ended early."},
    {"ts": "2026-11-13T11:00:00Z", "kind": "skills", "source": "system", "title": "New skill awaiting review"},
    {"ts": "2026-11-13T12:00:00Z", "kind": "cron", "source": "system", "title": "Cron job failed", "body": "exit 1"},
]) + "\n", encoding="utf-8")
(HOME / "security_events.jsonl").write_text("\n".join(json.dumps(x) for x in [
    {"timestamp": "2026-11-13T10:00:00+00:00", "event_type": "api_access", "operation": "GET /api/status", "outcome": "ok", "source": "dashboard", "metadata": {"secret": "do-not-show"}},
    {"timestamp": "2026-11-13T10:01:00+00:00", "event_type": "governance_decision", "operation": "shell rm -rf", "outcome": "denied", "source": "gate", "error": "denied by policy"},
    {"timestamp": "2026-11-13T10:02:00+00:00", "event_type": "api_access", "operation": "GET /x", "outcome": "not_found"},
]) + "\n", encoding="utf-8")

os.environ.update({"KIROCREW_HOME": str(HOME), "EVENT_VIEWER_DATA": str(DATA), "KIROCREW_PROXY_SECRET": SECRET})
spec = importlib.util.spec_from_file_location("kev_server", ROOT / "backend" / "server.py")
assert spec is not None and spec.loader is not None
srv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(srv)

HTTPD = srv.Server((srv.BIND_HOST, 0), srv.Handler)
PORT = HTTPD.server_address[1]
threading.Thread(target=HTTPD.serve_forever, daemon=True).start()
PREFIX = srv.PREFIX


def call(method: str, target: str, body: bytes = b"", *, sign: bool = True, secret: str = SECRET,
         nonce: str | None = None, ts: int | None = None):
    headers = {"Content-Type": "application/json"}
    if sign:
        ts = int(time.time()) if ts is None else ts
        nonce = nonce or secrets.token_hex(16)
        msg = f"v2:{ts}:{nonce}:{method}:{target}:{hashlib.sha256(body).hexdigest()}"
        headers["X-KiroCrew-Proxy-Nonce"] = nonce
        headers["X-KiroCrew-Proxy-V2"] = f"{ts}:{hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()}"
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{target}", data=body or None, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        with e:
            return e.code, json.loads(e.read() or b"{}")


def post(events) -> tuple[int, dict]:
    return call("POST", f"{PREFIX}/events", json.dumps(events).encode())


class Auth(unittest.TestCase):
    def test_binds_loopback_only(self):
        self.assertEqual(srv.BIND_HOST, "127.0.0.1")
        self.assertEqual(HTTPD.server_address[0], "127.0.0.1")

    def test_health_is_open(self):
        self.assertEqual(call("GET", "/health", sign=False)[0], 200)

    def test_unsigned_refused(self):
        self.assertEqual(call("GET", f"{PREFIX}/logs", sign=False)[0], 401)

    def test_wrong_secret_refused(self):
        self.assertEqual(call("GET", f"{PREFIX}/logs", secret="nope")[0], 401)

    def test_signed_accepted(self):
        code, body = call("GET", f"{PREFIX}/logs")
        self.assertEqual(code, 200)
        self.assertEqual([l["name"] for l in body["logs"]], ["application", "system", "security"])

    def test_replayed_nonce_refused(self):
        n, ts = secrets.token_hex(16), int(time.time())
        self.assertEqual(call("GET", f"{PREFIX}/logs", nonce=n, ts=ts)[0], 200)
        self.assertEqual(call("GET", f"{PREFIX}/logs", nonce=n, ts=ts)[0], 401)

    def test_stale_timestamp_refused(self):
        self.assertEqual(call("GET", f"{PREFIX}/logs", ts=int(time.time()) - 300)[0], 401)

    def test_signature_bound_to_target(self):
        # Signed for /logs but sent to /events: the target is part of the MAC.
        n, ts = secrets.token_hex(16), int(time.time())
        msg = f"v2:{ts}:{n}:GET:{PREFIX}/logs:{hashlib.sha256(b'').hexdigest()}"
        sig = hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}{PREFIX}/events?log=system",
                                     headers={"X-KiroCrew-Proxy-Nonce": n, "X-KiroCrew-Proxy-V2": f"{ts}:{sig}"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(cm.exception.code, 401)

    def test_no_secret_fails_closed(self):
        self.assertFalse(srv.verify_signature("1:abc", secrets.token_hex(16), "GET", "/", b"", secret=""))

    def test_oversized_body_refused(self):
        self.assertEqual(call("POST", f"{PREFIX}/events", b"x" * (srv.MAX_BODY + 1))[0], 413)


class Application(unittest.TestCase):
    def setUp(self):
        call("DELETE", f"{PREFIX}/events?log=application")

    def events(self, query: str = ""):
        return call("GET", f"{PREFIX}/events?log=application{query}")[1]["events"]

    def test_post_and_read(self):
        code, body = post({"source": "backup", "level": "warning", "message": "took 41 min", "data": {"min": 41}})
        self.assertEqual(code, 201)
        ev = self.events()[0]
        self.assertEqual((ev["source"], ev["level"], ev["data"]["min"], ev["via"]), ("backup", "warning", 41, "api"))

    def test_post_batch(self):
        code, body = post([{"source": "a", "message": "1"}, {"source": "b", "message": "2", "level": "error"}])
        self.assertEqual((code, len(body["ids"])), (201, 2))

    def test_post_invalid_rejected(self):
        self.assertEqual(post({"message": "no source"})[0], 400)
        self.assertEqual(post([{"source": "ok", "message": "x"}, {"source": ""}])[0], 400)
        self.assertEqual(self.events(), [])

    def test_unknown_level_becomes_information_and_control_chars_stripped(self):
        post({"source": "x", "level": "bogus", "message": "a\x00b\x1bc"})
        ev = self.events()[0]
        self.assertEqual((ev["level"], ev["message"]), ("information", "abc"))

    def test_filters(self):
        post([{"source": "a", "message": "disk full", "level": "error"}, {"source": "b", "message": "ok"}])
        self.assertEqual([e["message"] for e in self.events("&level=error")], ["disk full"])
        self.assertEqual([e["source"] for e in self.events("&q=ok")], ["b"])

    def test_inbox_ingest(self):
        srv.INBOX.mkdir(parents=True, exist_ok=True)
        f = srv.INBOX / "job.jsonl"
        f.write_text('{"source":"job","message":"one"}\n{"source":"job","level":"error","message":"two"}\nnot json\n')
        old = time.time() - 5
        os.utime(f, (old, old))
        self.assertEqual(srv.ingest_inbox(), 3)  # two events + one viewer warning about the bad line
        self.assertFalse(f.exists())
        msgs = {e["message"] for e in self.events()}
        self.assertIn("two", msgs)
        self.assertTrue(any("not valid events" in m for m in msgs))

    def test_inbox_skips_files_still_being_written(self):
        srv.INBOX.mkdir(parents=True, exist_ok=True)
        f = srv.INBOX / "fresh.jsonl"
        f.write_text('{"source":"job","message":"later"}\n')
        self.assertEqual(srv.ingest_inbox(), 0)
        self.assertTrue(f.exists())
        f.unlink()

    def test_cli_helper(self):
        srv.INBOX.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "KIRO_EVENT_INBOX": str(srv.INBOX)}
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "kiro-event"), "-s", "cli", "-l", "warning",
                            "-c", "Test", "--data", '{"n":1}', "from the CLI"], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        files = list(srv.INBOX.glob("*.jsonl"))
        self.assertEqual(len(files), 1)
        self.assertEqual(oct(files[0].stat().st_mode & 0o777), "0o600")
        old = time.time() - 5
        os.utime(files[0], (old, old))
        srv.ingest_inbox()
        ev = self.events()[0]
        self.assertEqual((ev["source"], ev["level"], ev["category"], ev["data"]), ("cli", "warning", "Test", {"n": 1}))

    def test_only_application_log_can_be_cleared(self):
        self.assertEqual(call("DELETE", f"{PREFIX}/events?log=security")[0], 400)


class CrewLogs(unittest.TestCase):
    def test_system_mapping(self):
        evs = {e["message"].split("\n")[0]: e for e in call("GET", f"{PREFIX}/events?log=system")[1]["events"]}
        self.assertEqual(evs["⚠️ A chat stopped"]["level"], "warning")
        self.assertEqual(evs["Cron job failed"]["level"], "error")
        self.assertEqual(evs["New skill awaiting review"]["level"], "information")

    def test_security_mapping_and_metadata_hidden(self):
        evs = call("GET", f"{PREFIX}/events?log=security")[1]["events"]
        by_op = {e["data"]["operation"]: e for e in evs}
        self.assertEqual(by_op["GET /api/status"]["level"], "success_audit")
        self.assertEqual(by_op["shell rm -rf"]["level"], "failure_audit")
        self.assertEqual(by_op["GET /x"]["level"], "information")
        self.assertNotIn("do-not-show", json.dumps(evs))

    def test_crew_logs_are_read_only(self):
        before = (HOME / "security_events.jsonl").read_bytes()
        call("GET", f"{PREFIX}/events?log=security")
        self.assertEqual((HOME / "security_events.jsonl").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
