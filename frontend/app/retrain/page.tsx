import { RetrainQueue } from "@/components/retrain-queue"
import { RetrainControls } from "@/components/retrain-controls"

export default function RetrainPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Retrain Queue</h1>
        <p className="text-muted-foreground mt-1">Manage labeled flows and trigger model retraining</p>
      </div>
      <RetrainControls />
      <RetrainQueue />
    </div>
  )
}
