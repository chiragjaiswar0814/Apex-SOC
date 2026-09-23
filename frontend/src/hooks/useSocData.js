/**
 * useSocData — custom hook
 * Polls all Apex-SOC API endpoints on a configurable interval.
 * Returns stats, incidents, topIPs, events, loading, and error state.
 */
import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '../api/client'

export function useSocData(intervalMs = 5000) {
  const [stats, setStats]       = useState(null)
  const [incidents, setIncidents] = useState([])
  const [topIPs, setTopIPs]     = useState([])
  const [events, setEvents]     = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const isMounted               = useRef(true)

  const fetchAll = useCallback(async () => {
    try {
      const [s, inc, ips, evts] = await Promise.all([
        api.getStats(),
        api.getIncidents(),
        api.getTopIPs(10),
        api.getEvents(300),
      ])
      if (!isMounted.current) return
      setStats(s)
      setIncidents(inc)
      setTopIPs(ips)
      setEvents(evts)
      setError(null)
    } catch (err) {
      if (!isMounted.current) return
      setError(err.message)
    } finally {
      if (isMounted.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    isMounted.current = true
    fetchAll()
    const timer = setInterval(fetchAll, intervalMs)
    return () => {
      isMounted.current = false
      clearInterval(timer)
    }
  }, [fetchAll, intervalMs])

  return { stats, incidents, topIPs, events, loading, error, refetch: fetchAll }
}
