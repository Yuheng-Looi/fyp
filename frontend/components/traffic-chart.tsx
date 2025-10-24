"use client"

import { Card } from "@/components/ui/card"
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts"

const data = [
  { name: "Normal", value: 87234, color: "#10b981" }, // green
  { name: "Attack", value: 2156, color: "#ef4444" }, // red
  { name: "Uncertain", value: 1543, color: "#f59e0b" }, // amber/yellow
]

export function TrafficChart() {
  return (
    <Card className="p-6">
      <h3 className="font-semibold mb-4">Traffic Classification</h3>
      <ResponsiveContainer width="100%" height={300}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            labelLine={false}
            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(1)}%`}
            outerRadius={100}
            fill="#8884d8"
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </Card>
  )
}
