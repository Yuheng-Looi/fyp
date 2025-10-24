import { Card } from "@/components/ui/card"
import { Activity, AlertTriangle, RefreshCw, Shield } from "lucide-react"

const metrics = [
  {
    title: "Total Flows Analyzed",
    value: "1,234,567",
    icon: Activity,
    color: "text-primary",
  },
  {
    title: "Abnormal Traffic",
    value: "2.4%",
    icon: AlertTriangle,
    color: "text-destructive",
  },
  {
    title: "Last Retrain",
    value: "2 days ago",
    icon: RefreshCw,
    color: "text-warning",
  },
  {
    title: "Model Version",
    value: "v3.2.1",
    icon: Shield,
    color: "text-success",
  },
]

export function MetricCards() {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {metrics.map((metric) => {
        const Icon = metric.icon
        return (
          <Card key={metric.title} className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">{metric.title}</p>
                <p className="text-2xl font-semibold mt-2">{metric.value}</p>
              </div>
              <Icon className={`h-8 w-8 ${metric.color}`} />
            </div>
          </Card>
        )
      })}
    </div>
  )
}
