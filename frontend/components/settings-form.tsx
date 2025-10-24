"use client"

import { Card } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useToast } from "@/hooks/use-toast"

export function SettingsForm() {
  const { toast } = useToast()

  const handleSave = () => {
    toast({
      title: "Settings Saved",
      description: "Your configuration has been updated",
    })
  }

  return (
    <div className="space-y-6">
      <Card className="p-6">
        <h3 className="font-semibold mb-4">Detection Settings</h3>
        <div className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="confidence">Confidence Threshold for Alerts (%)</Label>
            <Input id="confidence" type="number" defaultValue="85" min="0" max="100" />
            <p className="text-xs text-muted-foreground">
              Flows with confidence below this threshold will be marked as uncertain
            </p>
          </div>
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Auto-Retrain</Label>
              <p className="text-xs text-muted-foreground">Automatically retrain model when queue reaches threshold</p>
            </div>
            <Switch defaultChecked />
          </div>
          <div className="space-y-2">
            <Label htmlFor="threshold">Auto-Retrain Threshold</Label>
            <Input id="threshold" type="number" defaultValue="100" min="10" />
            <p className="text-xs text-muted-foreground">Number of labeled flows required to trigger auto-retrain</p>
          </div>
        </div>
      </Card>

      <Card className="p-6">
        <h3 className="font-semibold mb-4">Data Retention</h3>
        <div className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="retention">Log Retention Duration</Label>
            <Select defaultValue="30">
              <SelectTrigger id="retention">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="7">7 days</SelectItem>
                <SelectItem value="14">14 days</SelectItem>
                <SelectItem value="30">30 days</SelectItem>
                <SelectItem value="60">60 days</SelectItem>
                <SelectItem value="90">90 days</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">Flow records older than this will be automatically deleted</p>
          </div>
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Archive Old Models</Label>
              <p className="text-xs text-muted-foreground">Keep previous model versions for rollback</p>
            </div>
            <Switch defaultChecked />
          </div>
        </div>
      </Card>

      <Card className="p-6">
        <h3 className="font-semibold mb-4">Notifications</h3>
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Email Alerts</Label>
              <p className="text-xs text-muted-foreground">Send email notifications for detected attacks</p>
            </div>
            <Switch defaultChecked />
          </div>
          <div className="flex items-center justify-between">
            <div className="space-y-0.5">
              <Label>Retrain Notifications</Label>
              <p className="text-xs text-muted-foreground">Notify when model retraining is complete</p>
            </div>
            <Switch defaultChecked />
          </div>
        </div>
      </Card>

      <div className="flex justify-end">
        <Button onClick={handleSave}>Save Settings</Button>
      </div>
    </div>
  )
}
