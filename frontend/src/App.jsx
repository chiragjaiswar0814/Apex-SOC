/**
 * App.jsx — Root component
 * Wires the useSocData hook to the DashboardLayout.
 */
import DashboardLayout from './components/DashboardLayout'
import { useSocData } from './hooks/useSocData'

export default function App() {
  const { stats, incidents, topIPs, events, loading, error, refetch } = useSocData(5000)

  return (
    <DashboardLayout
      stats={stats}
      incidents={incidents}
      topIPs={topIPs}
      events={events}
      loading={loading}
      error={error}
      refetch={refetch}
    />
  )
}
