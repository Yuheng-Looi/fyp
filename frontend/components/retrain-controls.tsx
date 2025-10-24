"use client"

import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { RefreshCw, Trash2 } from "lucide-react"
import { useState } from "react"
import { useToast } from "@/hooks/use-toast"

export function RetrainControls() {
  const [isRetraining, setIsRetraining] = useState(false)
  const [progress, setProgress] = useState(0)
  const { toast } = useToast()

  const handleStartRetrain = () => {
    setIsRetraining(true)
    setProgress(0)

    const interval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval)
          setIsRetraining(false)
          toast({
            title: "Retraining Complete",
            description: "Model has been updated successfully",
          })
          return 100
        }
        return prev + 10
      })
    }, 500)
  }

  const handleClearQueue = () => {
    toast({
      title: "Queue Cleared",
      description: "All labeled flows have been removed",
    })
  }

  return (
    <Card className="p-6">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-semibold">Retrain Controls</h3>
            <p className="text-sm text-muted-foreground mt-1">
              {isRetraining ? "Model retraining in progress..." : "47 labeled flows ready for training"}
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={handleClearQueue} disabled={isRetraining}>
              <Trash2 className="h-4 w-4 mr-2" />
              Clear Queue
            </Button>
            <Button onClick={handleStartRetrain} disabled={isRetraining}>
              <RefreshCw className={`h-4 w-4 mr-2 ${isRetraining ? "animate-spin" : ""}`} />
              Start Retrain
            </Button>
          </div>
        </div>
        {isRetraining && (
          <div className="space-y-2">
            <Progress value={progress} />
            <p className="text-xs text-muted-foreground text-center">{progress}% complete</p>
          </div>
        )}
      </div>
    </Card>
  )
}
