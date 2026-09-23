/**
 * Apex-SOC API client
 * Central place for all fetch calls; respects Vite proxy in dev.
 */

const BASE = import.meta.env.VITE_API_URL ?? ''

async function apiFetch(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API ${res.status}: ${text}`)
  }
  return res.json()
}

export const api = {
  getStats:     () => apiFetch('/api/stats'),
  getIncidents: (params = '') => apiFetch(`/api/incidents${params}`),
  getTopIPs:    (limit = 10) => apiFetch(`/api/top-ips?limit=${limit}`),
  getEvents:    (limit = 200) => apiFetch(`/api/events?limit=${limit}`),
  ingestEvent:  (payload) => apiFetch('/api/ingest', { method: 'POST', body: JSON.stringify(payload) }),
}
