/**
 * LogIngestor — redesigned developer ingest panel.
 */
import { useState } from 'react'
import { Terminal, Send, CheckCircle2, XCircle, ChevronRight } from 'lucide-react'
import { api } from '../api/client'

const PRESETS = [
  { label: 'Failed SSH Login', color: '#ef4444',
    payload: { source: 'linux_auth', source_ip: '192.168.1.100', username: 'root', hostname: 'prod-web-01',
               message: 'Failed password for root from 192.168.1.100 port 22 ssh2' } },
  { label: 'Successful Login', color: '#22c55e',
    payload: { source: 'linux_auth', source_ip: '192.168.1.100', username: 'root', hostname: 'prod-web-01',
               message: 'Accepted password for root from 192.168.1.100 port 22 ssh2' } },
  { label: 'Sudo Escalation', color: '#f97316',
    payload: { source: 'linux_auth', source_ip: '192.168.1.100', username: 'root', hostname: 'prod-web-01',
               message: 'sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash' } },
  { label: 'SQL Injection', color: '#a855f7',
    payload: { source: 'nginx', source_ip: '10.0.0.55', hostname: 'prod-web-01',
               message: "GET /login?user=' OR '1'='1 HTTP/1.1 200 - Mozilla/5.0" } },
  { label: 'Windows Failure', color: '#3b82f6',
    payload: { source: 'windows_event', source_ip: '172.16.0.20', username: 'Administrator', hostname: 'WIN-DC-01',
               message: 'EventID=4625 Logon Failure: Unknown user name or bad password.' } },
]

export default function LogIngestor({ onIngest }) {
  const [raw, setRaw] = useState(JSON.stringify(PRESETS[0].payload, null, 2))
  const [active, setActive] = useState(0)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  function selectPreset(idx) {
    setActive(idx)
    setRaw(JSON.stringify(PRESETS[idx].payload, null, 2))
    setResult(null)
  }

  async function submit() {
    try {
      setLoading(true)
      setResult(null)
      const res = await api.ingestEvent(JSON.parse(raw))
      setResult({ ok: true, data: res })
      onIngest?.()
    } catch (err) {
      setResult({ ok: false, error: err.message })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card p-5 flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center gap-2.5">
        <div className="p-1.5 rounded-lg" style={{ background: 'rgba(74,222,128,0.1)' }}>
          <Terminal size={14} style={{ color: '#4ade80' }} />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-soc-heading tracking-tight">Log Ingestor</h2>
          <p className="section-label mt-0.5">Fire test events at the correlation engine</p>
        </div>
        <span className="ml-auto text-[10px] px-2 py-0.5 rounded-md font-mono"
          style={{ background: 'rgba(74,222,128,0.08)', color: '#4ade80', border: '1px solid rgba(74,222,128,0.15)' }}>
          DEV TOOL
        </span>
      </div>

      <div className="divider" />

      {/* Preset pills */}
      <div className="flex flex-wrap gap-2">
        {PRESETS.map((p, i) => (
          <button
            key={p.label}
            onClick={() => selectPreset(i)}
            className={`preset-pill ${i === active ? 'active' : ''}`}
            style={i === active ? {
              borderColor: `${p.color}40`,
              background: `${p.color}10`,
              color: p.color,
            } : {}}
          >
            <span className="inline-block w-1.5 h-1.5 rounded-full mr-1.5" style={{ background: p.color, verticalAlign: 'middle' }} />
            {p.label}
          </button>
        ))}
      </div>

      {/* Two-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* JSON editor */}
        <div className="flex flex-col gap-2">
          <span className="section-label">Payload</span>
          <textarea
            value={raw}
            onChange={e => setRaw(e.target.value)}
            rows={9}
            spellCheck={false}
            className="code-area w-full p-3"
          />
        </div>

        {/* Right column — button + result */}
        <div className="flex flex-col gap-3">
          <span className="section-label">Response</span>

          <button
            onClick={submit}
            disabled={loading}
            className="flex items-center justify-center gap-2 rounded-xl py-2.5 font-semibold text-sm transition-all"
            style={{
              background: loading ? 'rgba(74,222,128,0.08)' : 'rgba(74,222,128,0.12)',
              border: '1px solid rgba(74,222,128,0.2)',
              color: '#4ade80',
              cursor: loading ? 'not-allowed' : 'pointer',
            }}
            onMouseEnter={e => !loading && (e.currentTarget.style.background = 'rgba(74,222,128,0.18)')}
            onMouseLeave={e => !loading && (e.currentTarget.style.background = 'rgba(74,222,128,0.12)')}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="w-3 h-3 border-2 border-green-400 border-t-transparent rounded-full animate-spin" />
                Sending…
              </span>
            ) : (
              <>
                <Send size={13} />
                Ingest Event
                <ChevronRight size={13} />
              </>
            )}
          </button>

          {/* Result */}
          {result ? (
            <div
              className="flex-1 rounded-xl p-3 font-mono text-[11px] leading-relaxed overflow-auto animate-fade-in"
              style={{
                background: result.ok ? 'rgba(34,197,94,0.05)' : 'rgba(239,68,68,0.05)',
                border: `1px solid ${result.ok ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)'}`,
              }}
            >
              <div className="flex items-center gap-1.5 mb-2 font-semibold" style={{ color: result.ok ? '#4ade80' : '#f87171' }}>
                {result.ok ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
                {result.ok
                  ? result.data?.incident_promoted
                    ? '🚨 INCIDENT PROMOTED!'
                    : 'Ingested successfully'
                  : 'Error'}
              </div>
              <pre style={{ color: result.ok ? '#4ade80' : '#f87171', opacity: 0.8 }}>
                {result.ok ? JSON.stringify(result.data, null, 2) : result.error}
              </pre>
            </div>
          ) : (
            <div className="flex-1 rounded-xl flex items-center justify-center"
              style={{ background: 'rgba(255,255,255,0.02)', border: '1px dashed rgba(255,255,255,0.06)', minHeight: 120 }}>
              <p className="section-label">Fire an event to see the response</p>
            </div>
          )}
        </div>
      </div>

      {/* Tip */}
      <div className="flex items-start gap-2 rounded-lg p-3" style={{ background: 'rgba(245,158,11,0.05)', border: '1px solid rgba(245,158,11,0.1)' }}>
        <span style={{ color: '#f59e0b', fontSize: 10 }}>💡</span>
        <p style={{ fontSize: 10, color: '#78716c', lineHeight: 1.5 }}>
          <strong style={{ color: '#d97706' }}>Simulate a full breach:</strong> Send <em>Failed SSH Login</em> ×11 → <em>Successful Login</em> → <em>Sudo Escalation</em> to trigger a <strong style={{ color: '#f87171' }}>CRITICAL incident</strong> with a live risk score.
        </p>
      </div>
    </div>
  )
}
