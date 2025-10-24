"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { Shield, Activity, RefreshCw, BarChart3, Settings } from "lucide-react"

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: BarChart3 },
  { href: "/live-traffic", label: "Live Traffic", icon: Activity },
  { href: "/retrain", label: "Retrain", icon: RefreshCw },
  { href: "/model-status", label: "Model Status", icon: Shield },
  { href: "/settings", label: "Settings", icon: Settings },
]

export function Navigation() {
  const pathname = usePathname()

  return (
    <nav className="border-b border-border bg-card">
      <div className="container mx-auto px-4">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-2 py-4">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-mono text-lg font-semibold">IDS Monitor</span>
          </div>
          <div className="flex gap-1">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = pathname === item.href
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    "flex items-center gap-2 px-4 py-4 text-sm font-medium transition-colors border-b-2",
                    isActive
                      ? "border-primary text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground",
                  )}
                >
                  <Icon className="h-4 w-4" />
                  {item.label}
                </Link>
              )
            })}
          </div>
        </div>
      </div>
    </nav>
  )
}
