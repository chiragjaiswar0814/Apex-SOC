/**
 * DashboardLayout — redesigned shell with refined navbar, mesh background,
 * sidebar-free single-column grid, and polished footer.
 */
import { useState, useEffect, useRef } from 'react'
import { RefreshCw, ShieldAlert, WifiOff, Bell } from 'lucide-react'
import TopStats from './TopStats'
import EventTimeline from './EventTimeline'
import TopAttackers from './TopAttackers'
import IncidentFeed from './IncidentFeed'
import LogIngestor from './LogIngestor'

/* ── Live Clock ─────────────────────────────────────────────────────────── */
function LiveClock() {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  const iso = time.toISOString()
  const [date, rest] = iso.split('T')
  const hms = rest.split('.')[0]
  return (
    <div className="hidden md:flex flex-col items-end">
      <span className="font-mono text-[11px] font-semibold" style={{ color: '#334155' }}>
        {hms} <span style={{ color: '#1e293b' }}>UTC</span>
      </span>
      <span className="font-mono text-[10px]" style={{ color: '#1e293b' }}>{date}</span>
    </div>
  )
}

/* ── Navbar ──────────────────────────────────────────────────────────────── */
function NavBar({ online, onRefresh, refreshing, incidentCount }) {
  return (
    <header
      className="sticky top-0 z-50 flex items-center justify-between gap-4 px-6"
      style={{
        height: 56,
        background: 'rgba(2,4,10,0.85)',
        backdropFilter: 'blur(24px)',
        WebkitBackdropFilter: 'blur(24px)',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
      }}
    >
      {/* Brand */}
      <div className="flex items-center gap-3">
        <div className="flex items-center justify-center rounded-xl"
          style={{ width: 34, height: 34, background: 'linear-gradient(135deg, rgba(244,63,94,0.2) 0%, rgba(168,85,247,0.2) 100%)', border: '1px solid rgba(244,63,94,0.25)' }}>
          <ShieldAlert size={17} style={{ color: '#f43f5e' }} />
        </div>
        <div className="leading-none">
          <h1 className="gradient-text font-black text-base tracking-tight leading-none">APEX-SOC</h1>
          <p className="section-label mt-0.5 leading-none">Security Operations Center</p>
        </div>
      </div>

      {/* Right controls */}
      <div className="flex items-center gap-3">
        {/* Incident badge */}
        {incidentCount > 0 && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg"
            style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)' }}>
            <Bell size={11} style={{ color: '#f87171' }} />
            <span className="font-mono text-[10px] font-bold" style={{ color: '#f87171' }}>
              {incidentCount} INCIDENT{incidentCount > 1 ? 'S' : ''}
            </span>
          </div>
        )}

        {/* Live indicator */}
        <div className="flex items-center gap-1.5">
          {online
            ? <><div className="live-dot" /><span className="font-mono text-[10px] font-semibold" style={{ color: '#22c55e' }}>LIVE</span></>
            : <><WifiOff size={11} style={{ color: '#ef4444' }} /><span className="font-mono text-[10px] font-semibold" style={{ color: '#ef4444' }}>OFFLINE</span></>
          }
        </div>

        {/* Divider */}
        <div className="h-4 w-px" style={{ background: 'rgba(255,255,255,0.07)' }} />

        {/* Refresh */}
        <button
          onClick={onRefresh}
          disabled={refreshing}
          className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs transition-all"
          style={{
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.07)',
            color: '#475569',
            cursor: refreshing ? 'not-allowed' : 'pointer',
          }}
          onMouseEnter={e => !refreshing && (e.currentTarget.style.color = '#94a3b8')}
          onMouseLeave={e => !refreshing && (e.currentTarget.style.color = '#475569')}
        >
          <RefreshCw size={11} className={refreshing ? 'animate-spin' : ''} />
          <span className="hidden sm:inline">Refresh</span>
        </button>

        <LiveClock />
      </div>
    </header>
  )
}

/* ── Skeleton cards ───────────────────────────────────────────────────────── */
function SkeletonGrid() {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-3 gap-4">
        {[1,2,3].map(i => <div key={i} className="skeleton h-28 rounded-2xl" />)}
      </div>
      <div className="skeleton h-48 rounded-2xl" />
      <div className="grid grid-cols-2 gap-4">
        <div className="skeleton h-56 rounded-2xl" />
        <div className="skeleton h-56 rounded-2xl" />
      </div>
    </div>
  )
}

/* ── Main layout ─────────────────────────────────────────────────────────── */
export default function DashboardLayout({ stats, incidents, topIPs, events, loading, error, refetch }) {
  const [refreshing, setRefreshing] = useState(false)

  async function handleRefresh() {
    setRefreshing(true)
    await refetch()
    setRefreshing(false)
  }

  return (
    <div className="min-h-screen bg-mesh flex flex-col">
      <NavBar
        online={!error}
        onRefresh={handleRefresh}
        refreshing={refreshing}
        incidentCount={incidents?.length ?? 0}
      />

      <main className="flex-1 w-full max-w-screen-xl mx-auto px-4 sm:px-6 py-6 flex flex-col gap-5">

        {/* Error banner */}
        {error && (
          <div className="flex items-center gap-2 rounded-xl px-4 py-3 text-xs animate-slide-up"
            style={{ background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.15)', color: '#f87171' }}>
            <WifiOff size={13} />
            <span>Backend unreachable: <span className="font-mono">{error}</span> — ensure the backend is running on port 8000.</span>
          </div>
        )}

        {loading && !stats ? <SkeletonGrid /> : (
          <>
            {/* Row 1 — stat cards */}
            <TopStats stats={stats} />

            {/* Row 2 — timeline */}
            <EventTimeline events={events} />

            {/* Row 3 — two-column: attackers | incidents */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
              <TopAttackers topIPs={topIPs} />
              <IncidentFeed incidents={incidents} />
            </div>

            {/* Row 4 — ingestor */}
            <LogIngestor onIngest={refetch} />
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="px-6 py-4 flex items-center justify-between"
        style={{ borderTop: '1px solid rgba(255,255,255,0.04)' }}>
        <span className="font-mono text-[10px]" style={{ color: '#1e293b' }}>APEX-SOC v1.0.0</span>
        <span className="font-mono text-[10px]" style={{ color: '#1e293b' }}>MITRE ATT&CK® · Polling 5s · {events?.length ?? 0} events buffered</span>
        <span className="font-mono text-[10px]" style={{ color: '#1e293b' }}>© 2026</span>
      </footer>
    </div>
  )
}
