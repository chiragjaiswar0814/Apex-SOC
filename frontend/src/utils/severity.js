/**
 * Severity utilities shared across components.
 */

export const SEVERITY_ORDER = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

export function severityBadgeClass(severity) {
  const map = {
    CRITICAL: 'badge-critical',
    HIGH:     'badge-high',
    MEDIUM:   'badge-medium',
    LOW:      'badge-low',
    INFO:     'badge-info',
  }
  return map[severity?.toUpperCase()] ?? 'badge-info'
}

export function severityColor(severity) {
  const map = {
    CRITICAL: '#ef4444',
    HIGH:     '#f97316',
    MEDIUM:   '#eab308',
    LOW:      '#3b82f6',
    INFO:     '#64748b',
  }
  return map[severity?.toUpperCase()] ?? '#64748b'
}

export function riskScoreColor(score) {
  if (score >= 80) return '#ef4444'
  if (score >= 60) return '#f97316'
  if (score >= 40) return '#eab308'
  if (score >= 20) return '#3b82f6'
  return '#22c55e'
}

export function formatTimestamp(ts) {
  if (!ts) return '—'
  try {
    return new Intl.DateTimeFormat('en-US', {
      month:  'short',
      day:    '2-digit',
      hour:   '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(new Date(ts))
  } catch {
    return ts
  }
}

export function groupEventsByMinute(events) {
  const buckets = {}
  for (const evt of events) {
    try {
      const d = new Date(evt.timestamp)
      const key = `${d.getHours().toString().padStart(2,'0')}:${d.getMinutes().toString().padStart(2,'0')}`
      buckets[key] = (buckets[key] ?? 0) + 1
    } catch { /* skip */ }
  }
  return Object.entries(buckets)
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([time, count]) => ({ time, count }))
}
