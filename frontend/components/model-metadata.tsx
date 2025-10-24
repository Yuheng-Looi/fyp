import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Download } from "lucide-react"

const metadata = [
  { label: "Model Version", value: "v3.2.1" },
  { label: "Training Date", value: "January 12, 2025" },
  { label: "Training Duration", value: "2h 34m" },
  { label: "Training Samples", value: "1,234,567" },
  { label: "Accuracy", value: "98.5%" },
  { label: "Precision", value: "97.8%" },
  { label: "Recall", value: "96.9%" },
  { label: "F1 Score", value: "97.3%" },
]

export function ModelMetadata() {
  return (
    <Card className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h3 className="font-semibold">Current Model Metadata</h3>
        <Button variant="outline">
          <Download className="h-4 w-4 mr-2" />
          Download Model
        </Button>
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {metadata.map((item) => (
          <div key={item.label} className="space-y-1">
            <p className="text-xs text-muted-foreground">{item.label}</p>
            <p className="text-lg font-semibold">{item.value}</p>
          </div>
        ))}
      </div>
    </Card>
  )
}
