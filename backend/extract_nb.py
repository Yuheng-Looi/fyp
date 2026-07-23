import json

with open('/home/fyp2025/fyp/backend/fyp.ipynb', 'r', encoding='utf-8') as f:
    nb = json.load(f)

out_lines = []
for idx, cell in enumerate(nb.get('cells', [])):
    cell_type = cell.get('cell_type')
    source = "".join(cell.get('source', []))
    
    # We want to keep code cells containing keywords, and also the markdown cells right before them for context.
    if cell_type == 'code':
        if any(keyword in source.lower() for keyword in ['gnn', 'sage', 'torch_geometric', 'topologydataset', 'graph_dataset']):
            # Find preceding markdown cells for context
            context = []
            for prev_idx in range(max(0, idx-2), idx):
                prev_cell = nb['cells'][prev_idx]
                if prev_cell['cell_type'] == 'markdown':
                    context.append(f"Markdown Context [{prev_idx}]:\n" + "".join(prev_cell.get('source', [])) + "\n")
            
            out_lines.append(f"==================================================\n")
            out_lines.append(f"=== CELL {idx} (Code) ===\n")
            if context:
                out_lines.extend(context)
                out_lines.append("Code:\n")
            out_lines.append(source)
            out_lines.append("\n\n")

with open('/home/fyp2025/fyp/backend/gnn_cells.txt', 'w', encoding='utf-8') as f:
    f.writelines(out_lines)

print("GNN cells written to /home/fyp2025/fyp/backend/gnn_cells.txt")
