/**
 * EventTimeline — sleek Recharts area chart with spike detection.
 */
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ReferenceLine, ResponsiveContainer,
} from 'recharts'
import { groupEventsByMinute } from '../utils/severity'
import { Activity, TrendingUp } from 'lucide-react'

const SPIKE_MULTIPLIER = 2.0

function computeSpikes(data) {
  if (!data.length) return { mean: 0, threshold: 0, spikes: [] }
  const mean = data.reduce((s, d) => s + d.count, 0) / data.length
  const threshold = mean * SPIKE_MULTIPLIER
  return { mean, threshold, spikes: data.filter(d => d.count > threshold).map(d => d.time) }
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'rgba(13,21,38,0.95)',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 10,
      padding: '8px 12px',
      backdropFilter: 'blur(12px)',
    }}>
      <p style={{ fontSize: 10, color: '#475569', marginBottom: 4, fontFamily: 'JetBrains Mono' }}>{label}</p>
      <p style={{ fontSize: 13, color: '#3b82f6', fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
        {payload[0]?.value} <span style={{ fontSize: 10, color: '#475569', fontWeight: 400 }}>events</span>
      </p>
    </div>
  )
}

export default function EventTimeline({ events = [] }) {
  const data = groupEventsByMinute(events)
  const { threshold, spikes } = computeSpikes(data)
  const isEmpty = data.length === 0

  return (
    <div className="card p-5 flex flex-col gap-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg" style={{ background: 'rgba(59,130,246,0.1)' }}>
            <Activity size={14} style={{ color: '#3b82f6' }} />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-soc-heading tracking-tight">Event Volume Timeline</h2>
            <p className="section-label mt-0.5">
              {isEmpty ? 'Awaiting data' : `${data.length} data points`}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {spikes.length > 0 && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg"
              style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)' }}>
              <TrendingUp size={11} style={{ color: '#f87171' }} />
              <span style={{ fontSize: 10, color: '#f87171', fontWeight: 600, letterSpacing: '0.05em' }}>
                {spikes.length} SPIKE{spikes.length > 1 ? 'S' : ''}
              </span>
            </div>
          )}
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full" style={{ background: '#3b82f6' }} />
            <span className="section-label">Events / min</span>
          </div>
        </div>
      </div>

      {/* Chart area */}
      {isEmpty ? (
        <div className="h-44 flex flex-col items-center justify-center gap-2" style={{ borderRadius: 10, background: 'rgba(255,255,255,0.02)' }}>
          <Activity size={24} style={{ color: '#1e3a5f' }} />
          <p className="section-label">No event data yet — ingest logs to see the timeline</p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={180}>
          <AreaChart data={data} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
            <defs>
              <linearGradient id="blueGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%"   stopColor="#3b82f6" stopOpacity={0.25} />
                <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%"   stopColor="#ef4444" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
            </defs>

            <CartesianGrid strokeDasharray="2 6" stroke="rgba(255,255,255,0.04)" vertical={false} />

            <XAxis
              dataKey="time"
              tick={{ fill: '#334155', fontSize: 9, fontFamily: 'JetBrains Mono' }}
              tickLine={false} axisLine={false}
              interval="preserveStartEnd"
            />
            <YAxis
              tick={{ fill: '#334155', fontSize: 9, fontFamily: 'JetBrains Mono' }}
              tickLine={false} axisLine={false}
              allowDecimals={false}
            />

            <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'rgba(255,255,255,0.08)', strokeWidth: 1 }} />

            {threshold > 0 && (
              <ReferenceLine
                y={threshold}
                stroke="#ef4444" strokeDasharray="3 5" strokeOpacity={0.5} strokeWidth={1}
              />
            )}
            {spikes.map(t => (
              <ReferenceLine key={t} x={t} stroke="#ef4444" strokeOpacity={0.12} strokeWidth={16} />
            ))}

            <Area
              type="monotone" dataKey="count"
              stroke="#3b82f6" strokeWidth={1.5}
              fill="url(#blueGrad)"
              dot={false}
              activeDot={{ r: 3, fill: '#3b82f6', stroke: '#02040a', strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
