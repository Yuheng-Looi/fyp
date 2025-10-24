import { ModelMetadata } from "@/components/model-metadata"
import { RetrainHistory } from "@/components/retrain-history"

export default function ModelStatusPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Model Status</h1>
        <p className="text-muted-foreground mt-1">Current model information and training history</p>
      </div>
      <ModelMetadata />
      <RetrainHistory />
    </div>
  )
}
