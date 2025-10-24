import { MetricCards } from "@/components/metric-cards"
import { TrafficChart } from "@/components/traffic-chart"
import { AttackTypesChart } from "@/components/attack-types-chart"
import { TopSourcesTable } from "@/components/top-sources-table"

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Dashboard Overview</h1>
        <p className="text-muted-foreground mt-1">Real-time detection statistics and insights</p>
      </div>
      <MetricCards />
      <div className="grid gap-6 md:grid-cols-2">
        <TrafficChart />
        <AttackTypesChart />
      </div>
      <TopSourcesTable />
    </div>
  )
}
