export type FlowRecord = {
  id: string
  timestamp: string
  srcIp: string
  dstIp: string
  protocol: string
  srcPort: number
  dstPort: number
  packetCount: number
  byteCount: number
  prediction: "Normal" | "Attack" | "Uncertain"
  confidence: number
}

export type LabeledFlow = {
  id: string
  flowRecord: FlowRecord
  originalLabel: string
  manualLabel: "Benign" | "Attack"
  labeledBy: string
  labeledAt: string
}

// Simple localStorage-based store for managing labeled flows
export class TrafficStore {
  private static LABELED_FLOWS_KEY = 'labeled_flows'
  
  static getLabeledFlows(): LabeledFlow[] {
    if (typeof window === 'undefined') return []
    const stored = localStorage.getItem(this.LABELED_FLOWS_KEY)
    return stored ? JSON.parse(stored) : []
  }
  
  static addLabeledFlow(flowRecord: FlowRecord, label: "Benign" | "Attack", labeledBy: string = "admin"): void {
    if (typeof window === 'undefined') return
    
    const labeledFlows = this.getLabeledFlows()
    const newLabeledFlow: LabeledFlow = {
      id: `labeled_${flowRecord.id}_${Date.now()}`,
      flowRecord,
      originalLabel: flowRecord.prediction,
      manualLabel: label,
      labeledBy,
      labeledAt: new Date().toISOString()
    }
    
    labeledFlows.push(newLabeledFlow)
    localStorage.setItem(this.LABELED_FLOWS_KEY, JSON.stringify(labeledFlows))
  }
  
  static clearLabeledFlows(): void {
    if (typeof window === 'undefined') return
    localStorage.removeItem(this.LABELED_FLOWS_KEY)
  }
}

// Helper function to filter flows
export function filterFlows(
  flows: FlowRecord[], 
  searchQuery: string = "", 
  protocolFilter: string = "all", 
  predictionFilter: string = "all"
): FlowRecord[] {
  return flows.filter(flow => {
    // Search filter (IP addresses and ports)
    const searchLower = (searchQuery || "").toLowerCase()
    const matchesSearch = !searchQuery || 
      flow.srcIp.toLowerCase().includes(searchLower) ||
      flow.dstIp.toLowerCase().includes(searchLower) ||
      flow.srcPort.toString().includes(searchLower) ||
      flow.dstPort.toString().includes(searchLower)
    
    // Protocol filter
    const matchesProtocol = protocolFilter === 'all' || 
      flow.protocol.toLowerCase() === protocolFilter.toLowerCase()
    
    // Prediction filter
    const matchesPrediction = predictionFilter === 'all' || 
      flow.prediction.toLowerCase() === predictionFilter.toLowerCase()
    
    return matchesSearch && matchesProtocol && matchesPrediction
  })
}