"use client"

import { useState, useEffect } from "react"
import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { TrafficStore, LabeledFlow } from "@/lib/store"
import { RefreshCw, Trash2, Eye } from "lucide-react"
import { useToast } from "@/hooks/use-toast"
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { cn } from "@/lib/utils"

export function RetrainQueue() {
  const [labeledFlows, setLabeledFlows] = useState<LabeledFlow[]>([])
  const [selectedFlow, setSelectedFlow] = useState<LabeledFlow | null>(null)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const { toast } = useToast()

  // Load labeled flows from storage
  useEffect(() => {
    setLabeledFlows(TrafficStore.getLabeledFlows())
  }, [])

  const handleRefresh = () => {
    setIsRefreshing(true)
    setTimeout(() => {
      setLabeledFlows(TrafficStore.getLabeledFlows())
      setIsRefreshing(false)
      toast({
        title: "Queue refreshed",
        description: "Latest labeled flows have been loaded",
      })
    }, 500)
  }

  const handleClearQueue = () => {
    TrafficStore.clearLabeledFlows()
    setLabeledFlows([])
    toast({
      title: "Queue cleared",
      description: "All labeled flows have been removed",
    })
  }

  const getLabelColor = (label: string) => {
    switch (label) {
      case "Benign":
        return "text-success bg-success/10 border-success/20"
      case "Attack":
        return "text-destructive bg-destructive/10 border-destructive/20"
      default:
        return "text-muted-foreground bg-muted/10 border-muted/20"
    }
  }

  const getOriginalLabelColor = (label: string) => {
    switch (label) {
      case "Normal":
        return "text-blue-600 bg-blue-50 border-blue-200"
      case "Attack":
        return "text-red-600 bg-red-50 border-red-200"
      case "Uncertain":
        return "text-orange-600 bg-orange-50 border-orange-200"
      default:
        return "text-gray-600 bg-gray-50 border-gray-200"
    }
  }

  return (
    <>
      <Card>
        <div className="p-4 border-b flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h3 className="font-medium">Retrain Queue</h3>
            <Badge variant="outline" className="font-mono">
              {labeledFlows.length} labeled flows
            </Badge>
          </div>
          <div className="flex items-center gap-2">
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
            {labeledFlows.length > 0 && (
              <Button 
                variant="outline" 
                size="sm" 
                onClick={handleClearQueue}
                className="gap-2 text-destructive hover:text-destructive"
              >
                <Trash2 className="h-4 w-4" />
                Clear Queue
              </Button>
            )}
          </div>
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
                <TableHead>Original Label</TableHead>
                <TableHead>Manual Label</TableHead>
                <TableHead>Labeled By</TableHead>
                <TableHead>Labeled At</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {labeledFlows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={11} className="text-center text-muted-foreground py-8">
                    No labeled flows in the retrain queue
                    <br />
                    <span className="text-sm">Label flows in the Live Traffic tab to add them here</span>
                  </TableCell>
                </TableRow>
              ) : (
                labeledFlows.map((labeledFlow) => (
                  <TableRow key={labeledFlow.id} className="hover:bg-muted/50">
                    <TableCell className="font-mono text-xs">
                      {labeledFlow.flowRecord.timestamp}
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {labeledFlow.flowRecord.srcIp}
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {labeledFlow.flowRecord.dstIp}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono">
                        {labeledFlow.flowRecord.protocol}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right font-mono text-sm">
                      {labeledFlow.flowRecord.srcPort}
                    </TableCell>
                    <TableCell className="text-right font-mono text-sm">
                      {labeledFlow.flowRecord.dstPort}
                    </TableCell>
                    <TableCell>
                      <Badge className={cn("border", getOriginalLabelColor(labeledFlow.originalLabel))}>
                        {labeledFlow.originalLabel}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge className={cn("border", getLabelColor(labeledFlow.manualLabel))}>
                        {labeledFlow.manualLabel}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {labeledFlow.labeledBy}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {new Date(labeledFlow.labeledAt).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        onClick={() => setSelectedFlow(labeledFlow)} 
                        className="h-8"
                        title="View Details"
                      >
                        <Eye className="h-3 w-3" />
                      </Button>
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
            <SheetTitle>Labeled Flow Details</SheetTitle>
          </SheetHeader>
          {selectedFlow && (
            <div className="mt-6 space-y-6">
              <div className="space-y-4">
                <h3 className="font-semibold text-sm text-muted-foreground">Labeling Information</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Original Prediction</p>
                    <Badge className={cn("border mt-1", getOriginalLabelColor(selectedFlow.originalLabel))}>
                      {selectedFlow.originalLabel}
                    </Badge>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Manual Label</p>
                    <Badge className={cn("border mt-1", getLabelColor(selectedFlow.manualLabel))}>
                      {selectedFlow.manualLabel}
                    </Badge>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Labeled By</p>
                    <p className="text-sm mt-1">{selectedFlow.labeledBy}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Labeled At</p>
                    <p className="font-mono text-sm mt-1">
                      {new Date(selectedFlow.labeledAt).toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <h3 className="font-semibold text-sm text-muted-foreground">Flow Information</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Timestamp</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.flowRecord.timestamp}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Protocol</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.flowRecord.protocol}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Source IP</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.flowRecord.srcIp}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Source Port</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.flowRecord.srcPort}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Destination IP</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.flowRecord.dstIp}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Destination Port</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.flowRecord.dstPort}</p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <h3 className="font-semibold text-sm text-muted-foreground">Traffic Statistics</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground">Packet Count</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.flowRecord.packetCount.toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Byte Count</p>
                    <p className="font-mono text-sm mt-1">{selectedFlow.flowRecord.byteCount.toLocaleString()}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Model Confidence</p>
                    <p className="font-mono text-sm font-semibold mt-1">{selectedFlow.flowRecord.confidence}%</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Avg Packet Size</p>
                    <p className="font-mono text-sm mt-1">
                      {Math.round(selectedFlow.flowRecord.byteCount / selectedFlow.flowRecord.packetCount)} bytes
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </>
  )
}
