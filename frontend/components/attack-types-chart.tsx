"use client"

import { Card } from "@/components/ui/card"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts"
import { useState } from "react"

const data = [
  { name: "DDoS", count: 856, color: "#ef4444" }, // red
  { name: "Port Scan", count: 432, color: "#f97316" }, // orange
  { name: "Brute Force", count: 289, color: "#f59e0b" }, // amber
  { name: "SQL Injection", count: 178, color: "#eab308" }, // yellow
  { name: "XSS", count: 145, color: "#84cc16" }, // lime
  { name: "Other", count: 256, color: "#6b7280" }, // gray
]

export function AttackTypesChart() {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null)

  // Fixed pixel increase for hover effect (equivalent to ~20-30 pixels)
  const hoverIncrease = 6

  // Create enhanced data with hover effect
  const enhancedData = data.map((item, index) => ({
    ...item,
    count: hoveredIndex === index ? item.count + hoverIncrease : item.count,
    originalCount: item.count
  }))

  return (
    <Card className="p-6">
      <h3 className="font-semibold mb-4">Attack Types Distribution</h3>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={enhancedData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
          <XAxis dataKey="name" stroke="white" fontSize={12} />
          <YAxis stroke="white" fontSize={12} />
          <Tooltip
            cursor={false}
            contentStyle={{
              backgroundColor: "white",
              border: "1px solid #e5e7eb",
              borderRadius: "8px",
              color: "#1f2937",
              fontSize: "14px",
              padding: "8px 12px",
              boxShadow: "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)",
            }}
            labelStyle={{
              color: "#1f2937",
              fontSize: "14px",
              fontWeight: "500",
            }}
            formatter={(value, name) => [enhancedData[hoveredIndex || 0]?.originalCount || value, name]}
            position={{ x: undefined, y: undefined }}
            allowEscapeViewBox={{ x: false, y: true }}
          />
          <Bar 
            dataKey="count" 
            radius={[4, 4, 0, 0]}
            onMouseEnter={(data, index) => setHoveredIndex(index)}
            onMouseLeave={() => setHoveredIndex(null)}
          >
            {enhancedData.map((entry, index) => (
              <Cell 
                key={`cell-${index}`} 
                fill={entry.color}
                stroke={hoveredIndex === index ? entry.color : "none"}
                strokeWidth={hoveredIndex === index ? 6 : 0}
                style={{
                  filter: hoveredIndex === index ? "brightness(1.15) drop-shadow(0px 0px 4px rgba(255,255,255,0.3))" : "none",
                  transition: "all 0.15s ease-in-out"
                }}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Card>
  )
}
