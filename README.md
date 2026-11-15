# Kiro Event Viewer

A Kiro Crew app in the spirit of the classic late-90s workstation event viewer:
three logs, a type column with icons, filters, find, live refresh, and an Event
Properties dialog. Pairs with the [Kiro NT](https://github.com/jasonmimick-aws/kiront-theme) theme.

| Log | Where it comes from |
|---|---|
| **System** | Kiro Crew's notifications (`~/.kiro/crew/notifications.jsonl`), read-only |
| **Security** | Kiro Crew's security audit log (`~/.kiro/crew/security_events.jsonl`, newest 2000), read-only; outcomes map to Success Audit / Failure Audit |
| **Application** | events posted by your own services (this app's data) |

## Post an event from any service

**Shell / any script** — the bundled helper writes one event into the app's
owner-only inbox and renames it into place atomically. No network, no credentials:
the directory's permissions are the access control.

```bash
~/.kiro/crew/apps/kiro-event-viewer/tools/kiro-event --source nightly-backup --level warning "Backup took 41 minutes"
~/.kiro/crew/apps/kiro-event-viewer/tools/kiro-event -s deploy -l error -c Release -i 1001 "Deploy failed" --data '{"pr": 812}'
echo "disk at 91%" | ~/.kiro/crew/apps/kiro-event-viewer/tools/kiro-event -s disk-watch -l warning -
```

Tip: `ln -s ~/.kiro/crew/apps/kiro-event-viewer/tools/kiro-event ~/.local/bin/kiro-event`.

**Any language** — write JSON lines to a temporary file in
`~/.kiro/crew/apps/kiro-event-viewer/data/inbox/`, then rename it to `<name>.jsonl`.
The viewer picks it up within a few seconds and deletes it.

```json
{"source": "my-service", "level": "error", "message": "Queue is stuck", "category": "Jobs", "event_id": 42, "data": {"depth": 900}}
```

Fields: `source` and `message` are required; `level` is `information` (default),
`warning`, `error`, `success` or `failure`; `category`, `event_id` (0-65535), `ts`
(ISO 8601 or epoch seconds) and `data` (a JSON object up to 8 KB) are optional.
Bad lines are reported as a warning in the Application log.

**HTTP through Kiro Crew** — callers that already hold a Kiro Crew credential can
`POST /api/apps/kiro-event-viewer/events` with the same JSON (or a list of up to
100). The gateway authenticates the caller.

## Install

```bash
kirocrew app install ~/work/kiro-event-viewer && kirocrew app enable kiro-event-viewer
```

Kiro Crew asks you to trust the app (it is third-party). **Event Viewer** then
appears in the sidebar.

## Security

- The backend binds `127.0.0.1` only; the gateway proxies the page's requests to it.
- Every route except `/health` requires the gateway's signed `X-KiroCrew-Proxy-V2`
  header (HMAC with the per-app secret, fresh timestamp, single-use nonce), so another
  local process cannot bypass Kiro Crew's auth by calling the port directly. With no
  secret configured, every signed route refuses.
- Kiro Crew's own logs are never written. Security events show type, operation,
  outcome, agent, source and service; their `metadata` and identity fields are not shown.
- The inbox lives in the app's owner-only data directory; posted text is length-capped
  and stripped of control characters, and is displayed as text, never as HTML.

## Develop

```bash
python3 -m unittest discover -s tests -v   # backend: auth, posting, inbox, CLI, log mapping
python3 tools/make_icon.py                  # redraw assets/icon.png
```

`ui/index.mjs` is plain JavaScript (React via `window.__kirocrew_modules`, no build).
