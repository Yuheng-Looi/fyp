"use client"

import { useState } from "react"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Search, Filter, X } from "lucide-react"
import { Badge } from "@/components/ui/badge"

type TrafficFiltersProps = {
  searchQuery: string
  onSearchChange: (query: string) => void
  protocolFilter: string
  onProtocolChange: (protocol: string) => void
  predictionFilter: string
  onPredictionChange: (prediction: string) => void
  timeRangeFilter: string
  onTimeRangeChange: (timeRange: string) => void
}

export function TrafficFilters({
  searchQuery,
  onSearchChange,
  protocolFilter,
  onProtocolChange,
  predictionFilter,
  onPredictionChange,
  timeRangeFilter,
  onTimeRangeChange,
}: TrafficFiltersProps) {
  const [showAdvanced, setShowAdvanced] = useState(false)

  const clearAllFilters = () => {
    onSearchChange("")
    onProtocolChange("all")
    onPredictionChange("all")
    onTimeRangeChange("10min")
  }

  const hasActiveFilters = searchQuery || protocolFilter !== "all" || predictionFilter !== "all"

  return (
    <Card className="p-4 space-y-4">
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex-1 min-w-[200px]">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input 
              placeholder="Search by IP address or port number..." 
              className="pl-9" 
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
            />
            {searchQuery && (
              <Button
                variant="ghost"
                size="sm"
                className="absolute right-1 top-1/2 -translate-y-1/2 h-6 w-6 p-0"
                onClick={() => onSearchChange("")}
              >
                <X className="h-3 w-3" />
              </Button>
            )}
          </div>
        </div>
        
        <Select value={timeRangeFilter} onValueChange={onTimeRangeChange}>
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Time range" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="1min">Last 1 min</SelectItem>
            <SelectItem value="10min">Last 10 min</SelectItem>
            <SelectItem value="1hour">Last 1 hour</SelectItem>
            <SelectItem value="6hour">Last 6 hours</SelectItem>
            <SelectItem value="24hour">Last 24 hours</SelectItem>
          </SelectContent>
        </Select>

        <Button 
          variant="outline" 
          size="sm" 
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="gap-2"
        >
          <Filter className="h-4 w-4" />
          Filters
          {hasActiveFilters && (
            <Badge variant="secondary" className="h-4 min-w-4 px-1 text-xs">
              {[searchQuery ? 1 : 0, protocolFilter !== "all" ? 1 : 0, predictionFilter !== "all" ? 1 : 0].reduce((a, b) => a + b, 0)}
            </Badge>
          )}
        </Button>

        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={clearAllFilters}>
            Clear all
          </Button>
        )}
      </div>

      {showAdvanced && (
        <div className="border-t pt-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Protocol</label>
              <Select value={protocolFilter} onValueChange={onProtocolChange}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Protocol" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Protocols</SelectItem>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="icmp">ICMP</SelectItem>
                  <SelectItem value="http">HTTP</SelectItem>
                  <SelectItem value="https">HTTPS</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Prediction</label>
              <Select value={predictionFilter} onValueChange={onPredictionChange}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Prediction" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Predictions</SelectItem>
                  <SelectItem value="normal">Normal</SelectItem>
                  <SelectItem value="attack">Attack</SelectItem>
                  <SelectItem value="uncertain">Uncertain</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {hasActiveFilters && (
            <div className="mt-4 flex flex-wrap gap-2">
              <span className="text-sm text-muted-foreground">Active filters:</span>
              {searchQuery && (
                <Badge variant="secondary" className="gap-1">
                  Search: "{searchQuery}"
                  <X className="h-3 w-3 cursor-pointer" onClick={() => onSearchChange("")} />
                </Badge>
              )}
              {protocolFilter !== "all" && (
                <Badge variant="secondary" className="gap-1">
                  Protocol: {protocolFilter.toUpperCase()}
                  <X className="h-3 w-3 cursor-pointer" onClick={() => onProtocolChange("all")} />
                </Badge>
              )}
              {predictionFilter !== "all" && (
                <Badge variant="secondary" className="gap-1">
                  Prediction: {predictionFilter}
                  <X className="h-3 w-3 cursor-pointer" onClick={() => onPredictionChange("all")} />
                </Badge>
              )}
            </div>
          )}
        </div>
      )}
    </Card>
  )
}
