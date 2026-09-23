/**
 * TopAttackers — redesigned IP table with inline risk bars and flag indicators.
 */
import { Globe2, AlertOctagon, ShieldOff } from 'lucide-react'

function riskColor(score) {
  if (score >= 80) return '#ef4444'
  if (score >= 60) return '#f97316'
  if (score >= 40) return '#eab308'
  if (score >= 20) return '#3b82f6'
  return '#22c55e'
}

export default function TopAttackers({ topIPs = [] }) {
  return (
    <div className="card p-5 flex flex-col gap-4" style={{ minHeight: 280 }}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg" style={{ background: 'rgba(249,115,22,0.1)' }}>
            <Globe2 size={14} style={{ color: '#f97316' }} />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-soc-heading tracking-tight">Top Attackers</h2>
            <p className="section-label mt-0.5">Sorted by risk score</p>
          </div>
        </div>
        <span className="section-label">{topIPs.length} tracked</span>
      </div>

      <div className="divider" />

      {/* Empty */}
      {topIPs.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-2 py-8">
          <ShieldOff size={24} style={{ color: '#1e293b' }} />
          <p className="section-label">No suspicious IPs detected</p>
        </div>
      ) : (
        <>
          {/* Column headers */}
          <div className="grid gap-2 px-1" style={{ gridTemplateColumns: '18px 1fr 52px 52px 110px 68px' }}>
            {['#', 'Source IP', 'Events', 'Failed', 'Risk Score', 'Status'].map(h => (
              <span key={h} className="section-label">{h}</span>
            ))}
          </div>

          {/* Rows */}
          <div className="flex flex-col gap-0.5">
            {topIPs.map((row, idx) => {
              const color = riskColor(row.risk_score)
              return (
                <div
                  key={row.ip}
                  className="table-row grid gap-2 items-center rounded-lg px-1 py-2"
                  style={{ gridTemplateColumns: '18px 1fr 52px 52px 110px 68px' }}
                >
                  {/* Rank */}
                  <span className="font-mono text-xs" style={{ color: '#334155' }}>{idx + 1}</span>

                  {/* IP */}
                  <div className="flex items-center gap-2 min-w-0">
                    {row.is_flagged ? (
                      <span className="live-dot flex-shrink-0"
                        style={{ background: '#ef4444', boxShadow: '0 0 0 0 rgba(239,68,68,0.5)' }} />
                    ) : (
                      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: '#1e293b' }} />
                    )}
                    <span className="font-mono text-xs truncate" style={{ color: row.is_flagged ? '#fca5a5' : '#94a3b8' }}>
                      {row.ip}
                    </span>
                  </div>

                  {/* Events */}
                  <span className="font-mono text-xs" style={{ color: '#64748b' }}>
                    {row.event_count.toLocaleString()}
                  </span>

                  {/* Failed */}
                  <span className="font-mono text-xs font-semibold" style={{ color: row.failed_logins > 0 ? '#f87171' : '#334155' }}>
                    {row.failed_logins}
                  </span>

                  {/* Risk bar + number */}
                  <div className="flex items-center gap-2">
                    <div className="risk-track flex-1">
                      <div className="risk-fill" style={{ width: `${row.risk_score}%`, background: color }} />
                    </div>
                    <span className="font-mono text-xs font-bold w-7 text-right" style={{ color }}>
                      {Math.round(row.risk_score)}
                    </span>
                  </div>

                  {/* Status */}
                  {row.is_flagged ? (
                    <div className="flex items-center gap-1">
                      <AlertOctagon size={10} style={{ color: '#f87171' }} />
                      <span className="font-mono text-[10px] font-bold" style={{ color: '#f87171' }}>FLAGGED</span>
                    </div>
                  ) : (
                    <span className="font-mono text-[10px]" style={{ color: '#22c55e' }}>NORMAL</span>
                  )}
                </div>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}
