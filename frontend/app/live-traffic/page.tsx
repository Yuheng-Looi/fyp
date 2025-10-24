"use client"

import { useState } from "react"
import { LiveTrafficTable } from "@/components/live-traffic-table"
import { TrafficFilters } from "@/components/traffic-filters"

export default function LiveTrafficPage() {
  const [searchQuery, setSearchQuery] = useState("")
  const [protocolFilter, setProtocolFilter] = useState("all")
  const [predictionFilter, setPredictionFilter] = useState("all")
  const [timeRangeFilter, setTimeRangeFilter] = useState("10min")

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Live Traffic</h1>
        <p className="text-muted-foreground mt-1">Real-time network flow monitoring and classification</p>
      </div>
      
      <TrafficFilters 
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        protocolFilter={protocolFilter}
        onProtocolChange={setProtocolFilter}
        predictionFilter={predictionFilter}
        onPredictionChange={setPredictionFilter}
        timeRangeFilter={timeRangeFilter}
        onTimeRangeChange={setTimeRangeFilter}
      />
      
      <LiveTrafficTable 
        searchQuery={searchQuery}
        protocolFilter={protocolFilter}
        predictionFilter={predictionFilter}
        timeRangeFilter={timeRangeFilter}
      />
    </div>
  )
}
