/**
 * TopStats — redesigned metric cards with neon glows and large mono numbers.
 */
import { Activity, ShieldAlert, Zap } from 'lucide-react'

const CARDS = [
  {
    key: 'total_events',
    label: 'Total Events',
    sub: key => `${key} in last hour`,
    subKey: 'events_last_hour',
    Icon: Activity,
    color: '#3b82f6',
    glow: 'rgba(59,130,246,0.15)',
    border: 'rgba(59,130,246,0.2)',
    bg: 'rgba(59,130,246,0.06)',
  },
  {
    key: 'total_incidents',
    label: 'Active Incidents',
    sub: () => 'Correlated attack chains',
    Icon: ShieldAlert,
    color: '#f97316',
    glow: 'rgba(249,115,22,0.15)',
    border: 'rgba(249,115,22,0.2)',
    bg: 'rgba(249,115,22,0.06)',
    pulse: true,
  },
  {
    key: 'critical_alerts',
    label: 'Critical Alerts',
    sub: key => `${key} high severity`,
    subKey: 'high_alerts',
    Icon: Zap,
    color: '#ef4444',
    glow: 'rgba(239,68,68,0.15)',
    border: 'rgba(239,68,68,0.2)',
    bg: 'rgba(239,68,68,0.06)',
    pulse: true,
  },
]

export default function TopStats({ stats }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
      {CARDS.map(({ key, label, sub, subKey, Icon, color, glow, border, bg, pulse }) => {
        const value = stats?.[key] ?? 0
        const subVal = subKey ? (stats?.[subKey] ?? 0) : value
        const isActive = pulse && value > 0

        return (
          <div
            key={key}
            className="card relative overflow-hidden group cursor-default"
            style={{
              borderColor: border,
              boxShadow: isActive ? `0 0 40px ${glow}, 0 1px 3px rgba(0,0,0,0.5)` : undefined,
            }}
          >
            {/* Top accent line */}
            <div className="absolute top-0 left-0 right-0 h-px" style={{ background: `linear-gradient(to right, transparent, ${color}60, transparent)` }} />

            {/* Bg glow blob */}
            <div className="absolute -top-8 -right-8 w-32 h-32 rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-700 blur-2xl"
              style={{ background: glow }} />

            <div className="relative p-5 flex flex-col gap-4">
              {/* Label row */}
              <div className="flex items-center justify-between">
                <span className="section-label">{label}</span>
                <div className="p-2 rounded-xl relative" style={{ background: bg }}>
                  <Icon size={15} style={{ color }} />
                  {isActive && (
                    <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full"
                      style={{ background: color, animation: 'livePulse 2s infinite' }} />
                  )}
                </div>
              </div>

              {/* Big number */}
              <div>
                <div className="stat-num" style={{ color }}>
                  {Number(value).toLocaleString()}
                </div>
                <p className="text-xs text-soc-muted mt-1.5">
                  {sub(subVal)}
                </p>
              </div>

              {/* Bottom bar */}
              <div className="h-px w-full" style={{ background: `${color}18` }} />
              <div className="flex items-center gap-1.5">
                <div className="live-dot" style={{ background: color, boxShadow: 'none', width: 5, height: 5 }} />
                <span className="text-xs" style={{ color: `${color}90` }}>Live · polling every 5s</span>
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}
