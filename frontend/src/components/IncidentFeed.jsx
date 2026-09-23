/**
 * IncidentFeed — redesigned expandable incident cards with SVG arc gauge.
 */
import { useState } from 'react'
import { Siren, ChevronDown, Clock, Server, User, Shield } from 'lucide-react'
import { severityBadgeClass, formatTimestamp } from '../utils/severity'

function riskColor(score) {
  if (score >= 80) return '#ef4444'
  if (score >= 60) return '#f97316'
  if (score >= 40) return '#eab308'
  if (score >= 20) return '#3b82f6'
  return '#22c55e'
}

/** Circular SVG arc gauge */
function ArcGauge({ score }) {
  const color = riskColor(score)
  const R = 22, stroke = 4
  const circ = 2 * Math.PI * R
  const fill = circ - (score / 100) * circ
  return (
    <div className="relative flex-shrink-0" style={{ width: 52, height: 52 }}>
      <svg width="52" height="52" viewBox="0 0 52 52" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="26" cy="26" r={R} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={stroke} />
        <circle
          cx="26" cy="26" r={R} fill="none"
          stroke={color} strokeWidth={stroke}
          strokeDasharray={circ} strokeDashoffset={fill}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1s cubic-bezier(0.16,1,0.3,1), stroke 0.4s' }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="font-mono text-xs font-bold" style={{ color, fontSize: 11 }}>
          {Math.round(score)}
        </span>
      </div>
    </div>
  )
}

function SeverityBar({ severity }) {
  const map = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6', INFO: '#475569' }
  const color = map[severity] ?? '#475569'
  return (
    <div className="absolute left-0 top-4 bottom-4 w-0.5 rounded-full" style={{ background: color }} />
  )
}

function IncidentCard({ incident }) {
  const [open, setOpen] = useState(false)

  return (
    <div
      className="animate-slide-up relative rounded-xl overflow-hidden cursor-pointer"
      style={{
        background: 'rgba(15,23,42,0.7)',
        border: '1px solid rgba(255,255,255,0.06)',
        transition: 'border-color 0.2s',
      }}
      onMouseEnter={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)'}
      onMouseLeave={e => e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'}
      onClick={() => setOpen(o => !o)}
    >
      <SeverityBar severity={incident.severity} />

      <div className="pl-4 pr-3 py-3 flex flex-col gap-2.5">
        {/* Top row */}
        <div className="flex items-start gap-3">
          <ArcGauge score={incident.risk_score} />

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5 flex-wrap mb-1">
              <span className={`badge badge-${incident.severity?.toLowerCase()}`}>{incident.severity}</span>
              <span className="font-mono text-[9px]" style={{ color: '#334155' }}>
                #{incident.incident_id?.slice(0, 8)}
              </span>
            </div>
            <p className="text-xs font-semibold leading-snug" style={{ color: '#cbd5e1' }}>
              {incident.title}
            </p>
          </div>

          <ChevronDown
            size={14}
            style={{
              color: '#475569',
              flexShrink: 0,
              transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
              transition: 'transform 0.2s',
              marginTop: 2,
            }}
          />
        </div>

        {/* MITRE tags */}
        <div className="flex flex-wrap gap-1">
          {incident.mitre_techniques?.map(t => (
            <span key={t} className="mitre-tag">{t}</span>
          ))}
          {incident.mitre_tactics?.slice(0, 2).map(t => (
            <span key={t} className="mitre-tag" style={{ background: 'rgba(59,130,246,0.08)', color: '#93c5fd', borderColor: 'rgba(59,130,246,0.2)' }}>{t}</span>
          ))}
        </div>

        {/* Meta */}
        <div className="flex items-center gap-3 flex-wrap">
          <span className="flex items-center gap-1 font-mono text-[10px]" style={{ color: '#334155' }}>
            <Clock size={9} /> {formatTimestamp(incident.created_at)}
          </span>
          {incident.source_ip && (
            <span className="flex items-center gap-1 font-mono text-[10px]" style={{ color: '#f87171' }}>
              <Siren size={9} /> {incident.source_ip}
            </span>
          )}
          {incident.affected_hosts?.[0] && (
            <span className="flex items-center gap-1 font-mono text-[10px]" style={{ color: '#475569' }}>
              <Server size={9} /> {incident.affected_hosts[0]}
            </span>
          )}
          {incident.affected_users?.[0] && (
            <span className="flex items-center gap-1 font-mono text-[10px]" style={{ color: '#475569' }}>
              <User size={9} /> {incident.affected_users[0]}
            </span>
          )}
        </div>

        {/* Expandable attack chain */}
        {open && (
          <div className="animate-fade-in pt-2 mt-1 border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
            <p className="section-label mb-2">Attack Chain</p>
            <ol className="flex flex-col gap-1.5">
              {incident.attack_chain?.map((stage, i) => (
                <li key={i} className="flex items-start gap-2 font-mono text-[11px]" style={{ color: '#64748b' }}>
                  <span style={{ color: '#1e3a5f', minWidth: 16 }}>{i + 1}.</span>
                  <span style={{ color: '#94a3b8' }}>{stage}</span>
                </li>
              ))}
            </ol>
          </div>
        )}
      </div>
    </div>
  )
}

export default function IncidentFeed({ incidents = [] }) {
  return (
    <div className="card p-5 flex flex-col gap-4" style={{ minHeight: 280 }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg" style={{ background: 'rgba(239,68,68,0.1)' }}>
            <Siren size={14} style={{ color: '#ef4444' }} />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-soc-heading tracking-tight">Incident Feed</h2>
            <p className="section-label mt-0.5">Correlated attack chains</p>
          </div>
        </div>
        {incidents.length > 0 && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg"
            style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)' }}>
            <div className="live-dot" style={{ width: 6, height: 6, background: '#ef4444', boxShadow: '0 0 0 0 rgba(239,68,68,0.5)' }} />
            <span className="font-mono text-[10px] font-bold" style={{ color: '#f87171' }}>
              {incidents.length} OPEN
            </span>
          </div>
        )}
      </div>

      <div className="divider" />

      {/* Feed */}
      <div className="flex flex-col gap-2 overflow-y-auto" style={{ maxHeight: 480 }}>
        {incidents.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center gap-2 py-10">
            <Shield size={28} style={{ color: '#0f172a' }} />
            <p className="section-label">No incidents detected</p>
            <p className="text-xs" style={{ color: '#1e293b' }}>Correlation engine is monitoring…</p>
          </div>
        ) : (
          incidents.map(inc => <IncidentCard key={inc.incident_id} incident={inc} />)
        )}
      </div>
    </div>
  )
}
