import { Card } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

const history = [
  {
    version: "v3.2.1",
    date: "2025-01-12",
    duration: "2h 34m",
    samples: 1234567,
    accuracy: 98.5,
    status: "Active",
  },
  {
    version: "v3.2.0",
    date: "2025-01-10",
    duration: "2h 28m",
    samples: 1198234,
    accuracy: 98.2,
    status: "Archived",
  },
  {
    version: "v3.1.9",
    date: "2025-01-08",
    duration: "2h 31m",
    samples: 1156789,
    accuracy: 97.9,
    status: "Archived",
  },
  {
    version: "v3.1.8",
    date: "2025-01-06",
    duration: "2h 42m",
    samples: 1123456,
    accuracy: 97.6,
    status: "Archived",
  },
]

export function RetrainHistory() {
  return (
    <Card className="p-6">
      <h3 className="font-semibold mb-4">Training History</h3>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Version</TableHead>
            <TableHead>Training Date</TableHead>
            <TableHead>Duration</TableHead>
            <TableHead className="text-right">Samples</TableHead>
            <TableHead className="text-right">Accuracy</TableHead>
            <TableHead>Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {history.map((item) => (
            <TableRow key={item.version}>
              <TableCell className="font-mono font-semibold">{item.version}</TableCell>
              <TableCell>{item.date}</TableCell>
              <TableCell className="font-mono text-sm">{item.duration}</TableCell>
              <TableCell className="text-right font-mono">{item.samples.toLocaleString()}</TableCell>
              <TableCell className="text-right font-mono font-semibold">{item.accuracy}%</TableCell>
              <TableCell>
                <Badge variant={item.status === "Active" ? "default" : "outline"}>{item.status}</Badge>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Card>
  )
}
