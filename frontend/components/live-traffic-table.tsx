"use client"

import { useState, useEffect } from "react"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { useToast } from "@/hooks/use-toast"
import { CheckCircle2, AlertTriangle, Eye, RefreshCw } from "lucide-react"
import { cn } from "@/lib/utils"
import { FlowRecord, TrafficStore, filterFlows } from "@/lib/store"

const mockData: FlowRecord[] = [
  {
    id: "1",
    timestamp: "2025-01-14 10:23:45",
    srcIp: "192.168.1.105",
    dstIp: "10.0.0.52",
    protocol: "TCP",
    srcPort: 54321,
    dstPort: 443,
    packetCount: 1247,
    byteCount: 892456,
    prediction: "Normal",
    confidence: 98.5,
  },
  {
    id: "2",
    timestamp: "2025-01-14 10:23:46",
    srcIp: "172.16.0.88",
    dstIp: "10.0.0.52",
    protocol: "UDP",
    srcPort: 12345,
    dstPort: 53,
    packetCount: 5892,
    byteCount: 2456789,
    prediction: "Attack",
    confidence: 94.2,
  },
  {
    id: "3",
    timestamp: "2025-01-14 10:23:47",
    srcIp: "192.168.1.200",
    dstIp: "8.8.8.8",
    protocol: "TCP",
    srcPort: 49152,
    dstPort: 80,
    packetCount: 234,
    byteCount: 156789,
    prediction: "Uncertain",
    confidence: 62.8,
  },
  {
    id: "4",
    timestamp: "2025-01-14 10:23:48",
    srcIp: "10.0.0.15",
    dstIp: "192.168.1.1",
    protocol: "TCP",
    srcPort: 22,
    dstPort: 54890,
    packetCount: 456,
    byteCount: 234567,
    prediction: "Normal",
    confidence: 99.1,
  },
  {
    id: "5",
    timestamp: "2025-01-14 10:23:49",
    srcIp: "172.16.0.99",
    dstIp: "10.0.0.52",
    protocol: "ICMP",
    srcPort: 0,
    dstPort: 0,
    packetCount: 10000,
    byteCount: 5000000,
    prediction: "Attack",
    confidence: 97.3,
  },
  {
    id: "6",
    timestamp: "2025-01-14 10:23:50",
    srcIp: "203.0.113.42",
    dstIp: "192.168.1.100",
    protocol: "TCP",
    srcPort: 8080,
    dstPort: 80,
    packetCount: 789,
    byteCount: 345678,
    prediction: "Normal",
    confidence: 95.7,
  },
  {
    id: "7",
    timestamp: "2025-01-14 10:23:51",
    srcIp: "198.51.100.25",
    dstIp: "10.0.0.52",
    protocol: "UDP",
    srcPort: 1234,
    dstPort: 5353,
    packetCount: 25,
    byteCount: 12500,
    prediction: "Uncertain",
    confidence: 55.3,
  },
]

type LiveTrafficTableProps = {
  searchQuery: string
  protocolFilter: string
  predictionFilter: string
  timeRangeFilter: string
}

export function LiveTrafficTable({
  searchQuery,
  protocolFilter,
  predictionFilter,
  timeRangeFilter,
}: LiveTrafficTableProps) {
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null)
  const [flows, setFlows] = useState<FlowRecord[]>(mockData)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const { toast } = useToast()

  // Simulate real-time data updates
  useEffect(() => {
    const interval = setInterval(() => {
      // Add new mock flows occasionally
      if (Math.random() > 0.7) {
        const newFlow: FlowRecord = {
          id: `${Date.now()}`,
          timestamp: new Date().toISOString().slice(0, 19).replace('T', ' '),
          srcIp: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          dstIp: `10.0.0.${Math.floor(Math.random() * 255)}`,
          protocol: ["TCP", "UDP", "ICMP"][Math.floor(Math.random() * 3)],
          srcPort: Math.floor(Math.random() * 65535),
          dstPort: [80, 443, 22, 53, 25][Math.floor(Math.random() * 5)],
          packetCount: Math.floor(Math.random() * 10000),
          byteCount: Math.floor(Math.random() * 5000000),
          prediction: ["Normal", "Attack", "Uncertain"][Math.floor(Math.random() * 3)] as "Normal" | "Attack" | "Uncertain",
          confidence: Math.round((Math.random() * 40 + 60) * 10) / 10,
        }
        setFlows(prev => [newFlow, ...prev.slice(0, 19)]) // Keep only latest 20 flows
      }
    }, 5000) // Update every 5 seconds

    return () => clearInterval(interval)
  }, [])

  const handleLabel = (flow: FlowRecord, label: "Benign" | "Attack") => {
    TrafficStore.addLabeledFlow(flow, label)
    toast({
      title: `Flow labeled as ${label}`,
      description: `Traffic from ${flow.srcIp}:${flow.srcPort} has been added to retrain queue`,
      duration: 3000,
    })
  }

  const handleRefresh = async () => {
    setIsRefreshing(true)
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000))
    setIsRefreshing(false)
    toast({
      title: "Traffic data refreshed",
      description: "Latest network flows have been loaded",
    })
  }

  const filteredFlows = filterFlows(flows, searchQuery, protocolFilter, predictionFilter)

  const getPredictionColor = (prediction: string) => {
    switch (prediction) {
      case "Normal":
        return "text-success bg-success/10 border-success/20"
      case "Attack":
        return "text-destructive bg-destructive/10 border-destructive/20"
      case "Uncertain":
        return "text-warning bg-warning/10 border-warning/20"
      default:
        return ""
    }
  }

  const getRowColor = (prediction: string) => {
    switch (prediction) {
      case "Attack":
        return "bg-destructive/5 hover:bg-destructive/10"
      case "Uncertain":
        return "bg-warning/5 hover:bg-warning/10"
      default:
        return "hover:bg-muted/50"
    }
  }

  return (
    <>
      <Card>
        <div className="p-4 border-b flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h3 className="font-medium">Live Traffic Flows</h3>
            <Badge variant="outline" className="font-mono">
              {filteredFlows.length} flows
            </Badge>
          </div>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="gap-2"
          >
            <RefreshCw className={cn("h-4 w-4", isRefreshing && "animate-spin")} />
            Refresh
          </Button>
        </div>
        
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Timestamp</TableHead>
                <TableHead>Source IP</TableHead>
                <TableHead>Dest IP</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead className="text-right">Src Port</TableHead>
                <TableHead className="text-right">Dst Port</TableHead>
                <TableHead className="text-right">Packets</TableHead>
                <TableHead className="text-right">Bytes</TableHead>
                <TableHead>Prediction</TableHead>
                <TableHead className="text-right">Confidence</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredFlows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={11} className="text-center text-muted-foreground py-8">
                    No flows match your current filters
                  </TableCell>
                </TableRow>
              ) : (
                filteredFlows.map((flow) => (
                  <TableRow key={flow.id} className={cn("transition-colors", getRowColor(flow.prediction))}>
                    <TableCell className="font-mono text-xs">{flow.timestamp}</TableCell>
                    <TableCell className="font-mono text-sm">{flow.srcIp}</TableCell>
                    <TableCell className="font-mono text-sm">{flow.dstIp}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono">
                        {flow.protocol}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right font-mono text-sm">{flow.srcPort}</TableCell>
                    <TableCell className="text-right font-mono text-sm">{flow.dstPort}</TableCell>
                    <TableCell className="text-right font-mono text-sm">{flow.packetCount.toLocaleString()}</TableCell>
                    <TableCell className="text-right font-mono text-sm">{flow.byteCount.toLocaleString()}</TableCell>
                    <TableCell>
                      <Badge className={cn("border", getPredictionColor(flow.prediction))}>{flow.prediction}</Badge>
                    </TableCell>
                    <TableCell className="text-right font-mono font-semibold">{flow.confidence}%</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleLabel(flow, "Benign")}
                          className="h-8 text-xs hover:bg-success/20 hover:text-success transition-colors"
                          title="Label as Benign"
                        >
                          <CheckCircle2 className="h-3 w-3 mr-1" />
                          Benign
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleLabel(flow, "Attack")}
                          className="h-8 text-xs hover:bg-destructive/20 hover:text-destructive transition-colors"
                          title="Label as Attack"
                        >
                          <AlertTriangle className="h-3 w-3 mr-1" />
                          Attack
                        </Button>
                        <Button 
                          size="sm" 
                          variant="ghost" 
                          onClick={() => setSelectedFlow(flow)} 
                          className="h-8"
                          title="View Details"
                        >
                          <Eye className="h-3 w-3" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </Card>

      <Sheet open={!!selectedFlow} onOpenChange={() => setSelectedFlow(null)}>
        <SheetContent className="w-[600px] sm:max-w-[600px] overflow-y-auto">
          <SheetHeader>
            <SheetTitle>Flow Details</SheetTitle>
          </SheetHeader>
          {selectedFlow && (
            <div className="mt-6 space-y-6">
              <div className="space-y-4">
                <h3 className="font-semibold text-sm text-muted-foreground">Basic Information</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Timestamp</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.timestamp}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Protocol</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.protocol}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Source IP</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.srcIp}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Source Port</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.srcPort}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Destination IP</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.dstIp}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Destination Port</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.dstPort}</p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <h3 className="font-semibold text-sm text-muted-foreground">Traffic Statistics</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Packet Count</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.packetCount.toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Byte Count</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.byteCount.toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Avg Packet Size</p>
                    <p className="font-mono text-sm mt-1">
                      {Math.round(selectedFlow.byteCount / selectedFlow.packetCount)} bytes
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <h3 className="font-semibold text-sm text-muted-foreground">Model Prediction</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Classification</p>
                    <Badge className={cn("border mt-1", getPredictionColor(selectedFlow.prediction))}>
                      {selectedFlow.prediction}
                    </Badge>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Confidence</p>
                    <p className="font-mono text-sm font-semibold mt-1">{selectedFlow.confidence}%</p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <h3 className="font-semibold text-sm text-muted-foreground">Feature Breakdown</h3>
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between p-2 bg-muted rounded">
                    <span>Flow Duration</span>
                    <span>1.234s</span>
                  </div>
                  <div className="flex justify-between p-2 bg-muted rounded">
                    <span>Flow Bytes/s</span>
                    <span>{Math.round(selectedFlow.byteCount / 1.234).toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between p-2 bg-muted rounded">
                    <span>Flow Packets/s</span>
                    <span>{Math.round(selectedFlow.packetCount / 1.234).toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between p-2 bg-muted rounded">
                    <span>Fwd Packet Length Mean</span>
                    <span>{Math.round(selectedFlow.byteCount / selectedFlow.packetCount * 0.6)}</span>
                  </div>
                  <div className="flex justify-between p-2 bg-muted rounded">
                    <span>Bwd Packet Length Mean</span>
                    <span>{Math.round(selectedFlow.byteCount / selectedFlow.packetCount * 0.4)}</span>
                  </div>
                </div>
              </div>

              <div className="flex gap-2 pt-4 border-t">
                <Button
                  onClick={() => {
                    handleLabel(selectedFlow, "Benign")
                    setSelectedFlow(null)
                  }}
                  className="flex-1 bg-success hover:bg-success/90 text-white"
                >
                  <CheckCircle2 className="h-4 w-4 mr-2" />
                  Label as Benign
                </Button>
                <Button
                  onClick={() => {
                    handleLabel(selectedFlow, "Attack")
                    setSelectedFlow(null)
                  }}
                  variant="destructive"
                  className="flex-1"
                >
                  <AlertTriangle className="h-4 w-4 mr-2" />
                  Label as Attack
                </Button>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </>
  )
}
