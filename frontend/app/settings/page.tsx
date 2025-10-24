import { SettingsForm } from "@/components/settings-form"

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Settings</h1>
        <p className="text-muted-foreground mt-1">Configure system parameters and preferences</p>
      </div>
      <SettingsForm />
    </div>
  )
}
