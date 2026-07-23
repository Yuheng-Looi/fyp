import json

with open('/home/fyp2025/fyp/backend/fyp.ipynb', 'r', encoding='utf-8') as f:
    nb = json.load(f)

out_lines = []
for idx, cell in enumerate(nb.get('cells', [])):
    source = "".join(cell.get('source', []))
    if 'trichannel' in source.lower():
        out_lines.append(f"=== CELL {idx} ({cell.get('cell_type')}) ===\n")
        out_lines.append(source)
        out_lines.append("\n" + "="*50 + "\n")

with open('/home/fyp2025/fyp/backend/trichannel_cells.txt', 'w', encoding='utf-8') as f:
    f.writelines(out_lines)

print("Trichannel cells written to /home/fyp2025/fyp/backend/trichannel_cells.txt")
