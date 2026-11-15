// Kiro Event Viewer — page UI. Same host-module convention as Kiro Crew's own
// standalone apps: React and the app SDK come from window.__kirocrew_modules,
// there is no JSX and no build step. Every request goes through the SDK's
// permission-scoped client, so the gateway authenticates it and signs it for
// the backend.

const React = window.__kirocrew_modules.react
const { useAppApi } = window.__kirocrew_modules['@kirocrew/app-sdk']
const { useState, useEffect, useCallback, useRef, useMemo, createElement: h } = React

const BASE = '/api/apps/kiro-event-viewer'
const FONT = 'Tahoma, "Segoe UI", system-ui, sans-serif'
const RAISED = 'inset -1px -1px #0a0a0a, inset 1px 1px #ffffff, inset -2px -2px #808080, inset 2px 2px #dfdfdf'
const PRESSED = 'inset 1px 1px #0a0a0a, inset -1px -1px #ffffff, inset 2px 2px #808080, inset -2px -2px #dfdfdf'
const SUNKEN = 'inset 1px 1px #808080, inset -1px -1px #ffffff, inset 2px 2px #0a0a0a, inset -2px -2px #dfdfdf'
const WINDOW = 'inset -1px -1px #0a0a0a, inset 1px 1px #dfdfdf, inset -2px -2px #808080, inset 2px 2px #ffffff'

const svg = (body) => 'data:image/svg+xml,' + encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" shape-rendering="crispEdges">${body}</svg>`)
const ICONS = {
  information: svg('<circle cx="8" cy="8" r="7" fill="#0000c0" stroke="#000" stroke-width="1"/><rect x="7" y="3" width="2" height="2" fill="#fff"/><rect x="7" y="6.5" width="2" height="6" fill="#fff"/>'),
  warning: svg('<path d="M8 1 L15 14 L1 14 Z" fill="#ffff00" stroke="#000" stroke-width="1"/><rect x="7" y="5" width="2" height="5" fill="#000"/><rect x="7" y="11" width="2" height="2" fill="#000"/>'),
  error: svg('<circle cx="8" cy="8" r="7" fill="#e00000" stroke="#000" stroke-width="1"/><path d="M5 5 L11 11 M11 5 L5 11" stroke="#fff" stroke-width="2"/>'),
  success_audit: svg('<circle cx="5" cy="6" r="3.5" fill="#ffd000" stroke="#000" stroke-width="1"/><rect x="7.5" y="5" width="7" height="2" fill="#ffd000" stroke="#000" stroke-width=".6"/><rect x="11" y="7" width="1.5" height="3" fill="#000"/><rect x="13" y="7" width="1.5" height="2" fill="#000"/><circle cx="5" cy="6" r="1.2" fill="#000"/>'),
  failure_audit: svg('<path d="M4.5 7 V5 a3.5 3.5 0 0 1 7 0 V7" fill="none" stroke="#606060" stroke-width="1.6"/><rect x="2.5" y="7" width="11" height="8" fill="#c0c0c0" stroke="#000" stroke-width="1"/><rect x="7" y="9.5" width="2" height="3" fill="#000"/>'),
}
const TYPE_LABEL = {
  information: 'Information', warning: 'Warning', error: 'Error',
  success_audit: 'Success Audit', failure_audit: 'Failure Audit',
}
const LOGS = [
  { id: 'system', label: 'System' },
  { id: 'security', label: 'Security' },
  { id: 'application', label: 'Application' },
]
const VIEWS = [
  { id: '', label: 'All events' },
  { id: 'error', label: 'Errors' },
  { id: 'warning', label: 'Warnings' },
  { id: 'error,warning', label: 'Errors + warnings' },
  { id: 'success_audit,failure_audit', label: 'Audits' },
  { id: 'failure_audit', label: 'Failure audits' },
]

const fmtDate = (ts) => { const d = new Date(ts); return isNaN(d) ? '' : d.toLocaleDateString() }
const fmtTime = (ts) => { const d = new Date(ts); return isNaN(d) ? '' : d.toLocaleTimeString() }

function Btn({ pressed, style, children, ...rest }) {
  return h('button', {
    type: 'button', ...rest,
    style: {
      font: `12px ${FONT}`, color: rest.disabled ? '#808080' : '#000000', background: pressed ? '#dfdfdf' : '#c0c0c0',
      textShadow: rest.disabled ? '1px 1px #ffffff' : 'none', border: 0, boxShadow: pressed ? PRESSED : RAISED,
      cursor: rest.disabled ? 'default' : 'pointer', height: 24, padding: '0 10px', display: 'inline-flex',
      alignItems: 'center', gap: 6, ...style,
    },
  }, children)
}

function Field({ label, children }) {
  return h('div', { style: { display: 'grid', gridTemplateColumns: '78px 1fr', alignItems: 'baseline', gap: 6, margin: '3px 0' } },
    h('span', { style: { color: '#000000' } }, label), h('span', { style: { color: '#000000' } }, children))
}

function Properties({ ev, log, onClose, onPrev, onNext }) {
  useEffect(() => {
    const k = (e) => { if (e.key === 'Escape') onClose(); if (e.key === 'ArrowUp') onPrev(); if (e.key === 'ArrowDown') onNext() }
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [onClose, onPrev, onNext])
  const data = ev.data ? JSON.stringify(ev.data, null, 2) : ''
  return h('div', {
    style: { position: 'absolute', inset: 0, background: 'rgba(0,0,0,.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 20 },
    onPointerDown: (e) => { if (e.target === e.currentTarget) onClose() },
  },
  h('div', {
    role: 'dialog', 'aria-label': 'Event Properties',
    style: { width: 'min(520px, 94%)', padding: 3, background: '#c0c0c0', color: '#000000', boxShadow: WINDOW + ', 4px 4px 0 rgba(0,0,0,.35)', font: `12px ${FONT}` },
  },
  h('div', { style: { height: 20, padding: '0 4px', display: 'flex', alignItems: 'center', background: '#000080', color: '#ffffff', fontWeight: 700 } },
    h('span', { style: { flex: 1 } }, 'Event Properties'),
    h(Btn, { onClick: onClose, 'aria-label': 'Close', style: { height: 16, width: 18, padding: 0, justifyContent: 'center', fontSize: 10, fontWeight: 700 } }, '✕')),
  h('div', { style: { padding: '10px 12px' } },
    h('div', { style: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 16px' } },
      h('div', null,
        h(Field, { label: 'Date:' }, fmtDate(ev.ts)),
        h(Field, { label: 'Time:' }, fmtTime(ev.ts)),
        h(Field, { label: 'Type:' }, h('span', { style: { display: 'inline-flex', gap: 5, alignItems: 'center' } },
          h('img', { src: ICONS[ev.level] || ICONS.information, width: 16, height: 16, alt: '' }), TYPE_LABEL[ev.level] || ev.level))),
      h('div', null,
        h(Field, { label: 'Event ID:' }, String(ev.event_id || 0)),
        h(Field, { label: 'Source:' }, ev.source || ''),
        h(Field, { label: 'Category:' }, ev.category || 'None'),
        h(Field, { label: 'Log:' }, log))),
    h('div', { style: { marginTop: 8 } }, 'Description:'),
    h('div', {
      style: { marginTop: 3, height: 130, overflow: 'auto', padding: '4px 6px', background: '#ffffff', color: '#000000', boxShadow: SUNKEN, whiteSpace: 'pre-wrap', userSelect: 'text' },
    }, ev.message),
    data && h('div', { style: { marginTop: 8 } }, 'Data:'),
    data && h('pre', {
      style: { margin: '3px 0 0', maxHeight: 120, overflow: 'auto', padding: '4px 6px', background: '#ffffff', color: '#000000', boxShadow: SUNKEN, font: '11px Menlo, Consolas, monospace', userSelect: 'text' },
    }, data)),
  h('div', { style: { display: 'flex', justifyContent: 'space-between', padding: '0 12px 10px' } },
    h('div', { style: { display: 'flex', gap: 4 } },
      h(Btn, { onClick: onPrev, 'aria-label': 'Previous event' }, '↑'),
      h(Btn, { onClick: onNext, 'aria-label': 'Next event' }, '↓')),
    h(Btn, { onClick: onClose, style: { width: 76, justifyContent: 'center' } }, 'Close'))))
}

function HowTo({ inbox, onClose }) {
  const code = (t) => h('pre', {
    style: { margin: '3px 0 8px', padding: '5px 7px', background: '#000000', color: '#c0c0c0', font: '11px Menlo, Consolas, monospace', whiteSpace: 'pre-wrap', userSelect: 'text' },
  }, t)
  return h('div', { style: { margin: '0 3px 3px', padding: '8px 10px', background: '#ffffe1', color: '#000000', border: '1px solid #000000', position: 'relative' } },
    h(Btn, { onClick: onClose, 'aria-label': 'Close', style: { position: 'absolute', right: 6, top: 6, height: 18, padding: '0 6px' } }, '✕'),
    h('b', null, 'Post an event from any service'), h('div', { style: { marginTop: 4 } }, 'From a shell or script, with the helper in this app (no network, no credentials):'),
    code('kiro-event --source nightly-backup --level warning "Backup took 41 minutes"\nkiro-event -s deploy -l error -c Release -i 1001 "Deploy failed" --data \'{"pr": 812}\''),
    h('div', null, 'Or drop JSON lines into the inbox; any language can do this:'),
    code(`${inbox || '~/.kiro/crew/apps/kiro-event-viewer/data/inbox'}/<name>.jsonl\n{"source": "my-service", "level": "error", "message": "Queue is stuck", "category": "Jobs", "event_id": 42, "data": {"depth": 900}}`),
    h('div', null, 'Levels: information, warning, error, success, failure. Write to a temporary name and rename it to .jsonl when done; files are picked up within a few seconds.'))
}

function TestEvent({ onSend, onClose }) {
  const [source, setSource] = useState('my-service')
  const [level, setLevel] = useState('information')
  const [message, setMessage] = useState('Hello from Kiro Event Viewer.')
  const input = { font: `12px ${FONT}`, color: '#000000', background: '#ffffff', border: 0, boxShadow: SUNKEN, padding: '3px 5px', height: 22 }
  return h('div', { style: { margin: '0 3px 3px', padding: '8px 10px', background: '#c0c0c0', color: '#000000', boxShadow: WINDOW, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' } },
    h('b', null, 'Log an event:'),
    h('input', { 'aria-label': 'Source', value: source, onChange: (e) => setSource(e.target.value), style: { ...input, width: 130 } }),
    h('select', { 'aria-label': 'Level', value: level, onChange: (e) => setLevel(e.target.value), style: { ...input, height: 22 } },
      ...['information', 'warning', 'error', 'success', 'failure'].map((l) => h('option', { key: l, value: l }, l))),
    h('input', { 'aria-label': 'Message', value: message, onChange: (e) => setMessage(e.target.value), style: { ...input, flex: 1, minWidth: 180 } }),
    h(Btn, { onClick: () => onSend({ source, level, message }), disabled: !source.trim() || !message.trim() }, 'Log it'),
    h(Btn, { onClick: onClose }, 'Done'))
}

export default function KiroEventViewer() {
  const api = useAppApi()
  const [log, setLog] = useState('system')
  const [view, setView] = useState('')
  const [q, setQ] = useState('')
  const [rows, setRows] = useState([])
  const [meta, setMeta] = useState({ total: 0, matched: 0 })
  const [info, setInfo] = useState({ computer: 'LOCAL', inbox: '' })
  const [sel, setSel] = useState(null)
  const [open, setOpen] = useState(null)
  const [err, setErr] = useState('')
  const [auto, setAuto] = useState(true)
  const [panel, setPanel] = useState(null) // 'howto' | 'test' | null
  const qRef = useRef(q)
  qRef.current = q

  const load = useCallback(async () => {
    try {
      const p = new URLSearchParams({ log, limit: '500' })
      if (view) p.set('level', view)
      if (qRef.current.trim()) p.set('q', qRef.current.trim())
      const res = await api.get(`${BASE}/events?${p}`)
      setRows(res.events || []); setMeta({ total: res.total || 0, matched: res.matched || 0 }); setErr('')
    } catch (e) {
      setErr(String((e && e.message) || e))
    }
  }, [api, log, view])

  useEffect(() => { api.get(`${BASE}/logs`).then((r) => setInfo({ computer: r.computer || 'LOCAL', inbox: r.inbox || '' })).catch(() => {}) }, [api])
  useEffect(() => { setSel(null); load() }, [load])
  useEffect(() => {
    if (!auto) return undefined
    const id = setInterval(() => { if (!document.hidden) load() }, 5000)
    return () => clearInterval(id)
  }, [auto, load])

  const idx = useMemo(() => rows.findIndex((r) => r.id === (open && open.id)), [rows, open])
  const step = (d) => { const n = idx + d; if (n >= 0 && n < rows.length) { setOpen(rows[n]); setSel(rows[n].id) } }
  const logLabel = LOGS.find((l) => l.id === log).label

  const send = async (ev) => {
    try { await api.post(`${BASE}/events`, ev); if (log !== 'application') setLog('application'); else load() } catch (e) { setErr(String((e && e.message) || e)) }
  }
  const clear = async () => {
    if (!window.confirm('Clear every event in the Application log? This cannot be undone.')) return
    try { await api.del(`${BASE}/events?log=application`); load() } catch (e) { setErr(String((e && e.message) || e)) }
  }

  const th = (label, w) => h('th', {
    style: { position: 'sticky', top: 0, zIndex: 1, textAlign: 'left', fontWeight: 400, padding: '2px 6px', background: '#c0c0c0', color: '#000000', boxShadow: RAISED, width: w, whiteSpace: 'nowrap' },
  }, label)
  const td = (content, extra) => h('td', { style: { padding: '1px 6px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', ...extra } }, content)

  return h('div', {
    style: { position: 'relative', flex: 1, height: '100%', minHeight: 420, display: 'flex', flexDirection: 'column', padding: 3, background: '#c0c0c0', color: '#000000', font: `12px ${FONT}`, boxShadow: WINDOW },
  },
  h('div', { style: { height: 22, flex: '0 0 22px', padding: '0 6px', display: 'flex', alignItems: 'center', gap: 6, background: '#000080', color: '#ffffff', fontWeight: 700 } },
    h('img', { src: ICONS.information, width: 14, height: 14, alt: '' }),
    `Event Viewer - ${logLabel} Log on \\\\${info.computer}`),
  h('div', { role: 'toolbar', style: { display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 4, padding: '4px 2px' } },
    h('span', { style: { margin: '0 2px 0 4px' } }, 'Log:'),
    ...LOGS.map((l) => h(Btn, { key: l.id, pressed: log === l.id, 'aria-pressed': log === l.id, onClick: () => setLog(l.id) }, l.label)),
    h('span', { style: { width: 2, height: 22, margin: '0 4px', boxShadow: 'inset 1px 0 #808080, inset -1px 0 #ffffff' } }),
    h('label', { style: { display: 'inline-flex', alignItems: 'center', gap: 4 } }, 'View:',
      h('select', { value: view, onChange: (e) => setView(e.target.value), style: { font: `12px ${FONT}`, height: 22, color: '#000000', background: '#ffffff', border: 0, boxShadow: SUNKEN } },
        ...VIEWS.map((v) => h('option', { key: v.id, value: v.id }, v.label)))),
    h('input', {
      'aria-label': 'Find', placeholder: 'Find…', value: q, onChange: (e) => setQ(e.target.value), onKeyDown: (e) => { if (e.key === 'Enter') load() },
      style: { font: `12px ${FONT}`, height: 22, width: 160, padding: '0 5px', color: '#000000', background: '#ffffff', border: 0, boxShadow: SUNKEN },
    }),
    h(Btn, { onClick: load }, 'Refresh'),
    h('label', { style: { display: 'inline-flex', alignItems: 'center', gap: 3 } }, h('input', { type: 'checkbox', checked: auto, onChange: (e) => setAuto(e.target.checked) }), 'Auto'),
    h('span', { style: { flex: 1 } }),
    h(Btn, { pressed: panel === 'test', onClick: () => setPanel(panel === 'test' ? null : 'test') }, 'Log event…'),
    h(Btn, { pressed: panel === 'howto', onClick: () => setPanel(panel === 'howto' ? null : 'howto') }, 'How to post'),
    h(Btn, { onClick: clear, disabled: log !== 'application', title: log === 'application' ? 'Clear the Application log' : 'Kiro Crew logs are read-only here' }, 'Clear log')),
  panel === 'howto' && h(HowTo, { inbox: info.inbox, onClose: () => setPanel(null) }),
  panel === 'test' && h(TestEvent, { onSend: send, onClose: () => setPanel(null) }),
  err && h('div', { role: 'alert', style: { margin: '0 3px 3px', padding: '6px 8px', display: 'flex', gap: 8, alignItems: 'center', background: '#ffffff', color: '#000000', boxShadow: SUNKEN } },
    h('img', { src: ICONS.error, width: 16, height: 16, alt: '' }),
    h('span', null, 'The event log service did not answer. ', h('span', { style: { color: '#404040' } }, err))),
  h('div', { style: { flex: 1, minHeight: 0, overflow: 'auto', margin: '0 3px', background: '#ffffff', color: '#000000', boxShadow: SUNKEN, padding: 2 } },
    h('table', { style: { width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed', font: `12px ${FONT}` } },
      h('thead', null, h('tr', null, th('Type', 120), th('Date', 86), th('Time', 86), th('Source', 160), th('Category', 120), th('Event', 52), th('Description'))),
      h('tbody', null, ...rows.map((r) => {
        const active = sel === r.id
        return h('tr', {
          key: r.id, tabIndex: 0, 'aria-selected': active,
          onClick: () => setSel(r.id), onDoubleClick: () => setOpen(r),
          onKeyDown: (e) => { if (e.key === 'Enter') setOpen(r) },
          style: { cursor: 'default', background: active ? '#000080' : 'transparent', color: active ? '#ffffff' : '#000000', outline: 'none' },
        },
        td(h('span', { style: { display: 'inline-flex', alignItems: 'center', gap: 5 } },
          h('img', { src: ICONS[r.level] || ICONS.information, width: 16, height: 16, alt: '' }), TYPE_LABEL[r.level] || r.level)),
        td(fmtDate(r.ts)), td(fmtTime(r.ts)), td(r.source), td(r.category || 'None'), td(String(r.event_id || 0)),
        td((r.message || '').split('\n')[0], { color: active ? '#ffffff' : '#404040' }))
      })),
      !rows.length && h('tbody', null, h('tr', null, h('td', { colSpan: 7, style: { padding: 16, textAlign: 'center', color: '#404040' } },
        log === 'application' ? 'No events yet. Use "How to post" to send your first one.' : 'No events match this view.'))))),
  h('div', { style: { display: 'flex', gap: 3, padding: '3px 3px 1px' } },
    h('span', { style: { flex: 1, padding: '2px 6px', boxShadow: 'inset 1px 1px #808080, inset -1px -1px #ffffff' } },
      `${logLabel} Log on \\\\${info.computer}`),
    h('span', { style: { padding: '2px 8px', boxShadow: 'inset 1px 1px #808080, inset -1px -1px #ffffff' } },
      meta.matched === meta.total ? `${meta.total} event(s)` : `${meta.matched} of ${meta.total} event(s)`),
    h('span', { style: { padding: '2px 8px', boxShadow: 'inset 1px 1px #808080, inset -1px -1px #ffffff' } }, auto ? 'Live' : 'Paused')),
  open && h(Properties, { ev: open, log: logLabel, onClose: () => setOpen(null), onPrev: () => step(-1), onNext: () => step(1) }))
}
