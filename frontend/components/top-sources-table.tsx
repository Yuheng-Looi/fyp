import { Card } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

const topSources = [
  { ip: "192.168.1.105", flows: 45678, bytes: "2.3 GB", threats: 0 },
  { ip: "172.16.0.88", flows: 23456, bytes: "1.8 GB", threats: 234 },
  { ip: "10.0.0.52", flows: 18934, bytes: "1.2 GB", threats: 12 },
  { ip: "192.168.1.200", flows: 15678, bytes: "987 MB", threats: 5 },
  { ip: "172.16.0.99", flows: 12345, bytes: "756 MB", threats: 189 },
]

export function TopSourcesTable() {
  return (
    <Card className="p-6">
      <h3 className="font-semibold mb-4">Top Source IPs by Traffic Volume</h3>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Source IP</TableHead>
            <TableHead className="text-right">Total Flows</TableHead>
            <TableHead className="text-right">Total Bytes</TableHead>
            <TableHead className="text-right">Threats Detected</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {topSources.map((source) => (
            <TableRow key={source.ip}>
              <TableCell className="font-mono">{source.ip}</TableCell>
              <TableCell className="text-right font-mono">{source.flows.toLocaleString()}</TableCell>
              <TableCell className="text-right font-mono">{source.bytes}</TableCell>
              <TableCell className="text-right font-mono">
                <span className={source.threats > 0 ? "text-destructive font-semibold" : ""}>{source.threats}</span>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  )
}
