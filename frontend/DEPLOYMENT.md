# Flow Dashboard Deployment Guide

## Quick Start (Development)

```bash
cd /home/yuheng/ryu-project
source venv/bin/activate
python3 server.py
```

Access at: http://127.0.0.1:5000 or http://203.80.21.40:5000

## Production Deployment

### 1. Deploy Systemd Service

```bash
sudo cp flow-dashboard.service.sample /etc/systemd/system/flow-dashboard.service
sudo systemctl daemon-reload
sudo systemctl enable flow-dashboard
sudo systemctl start flow-dashboard
sudo systemctl status flow-dashboard
```

### 2. Deploy NGINX Reverse Proxy

```bash
sudo cp nginx.flow-dashboard.sample /etc/nginx/sites-available/flow-dashboard
sudo ln -sf /etc/nginx/sites-available/flow-dashboard /etc/nginx/sites-enabled/flow-dashboard
sudo nginx -t
sudo systemctl reload nginx
```

### 3. Open Firewall (if needed)

```bash
sudo ufw allow 80/tcp
```

Access at: http://203.80.21.40 or http://10.100.10.131

## Features

### PCAP Analysis Mode
1. Upload PCAP file
2. (Optional) Upload labels CSV with columns: src,dst,sport,dport,proto,label
3. Check "Has Labels" if labels provided
4. View metrics: accuracy, recall, F1, confusion matrix
5. View flow-by-flow predictions with 5-tuple, action, and correctness

### Live Monitor Mode
1. Enter interface name (e.g., `s1-snoop`)
2. Click START
3. View real-time flow classifications
4. Click STOP to halt capture

## API Endpoints

- `GET /` - Serve dashboard
- `POST /process_pcap` - Process uploaded PCAP with optional labels
- `POST /start_iface` - Start live capture on interface
- `POST /stop_iface` - Stop live capture
- `GET /flows` - Get recent live flows

## Dependencies

- Flask backend (Python 3.12)
- CICFlowMeter-aligned feature extraction
- External classifier API at 10.100.10.15:8000/predict
- Scapy, NumPy, Requests

## JSON Schema

### /process_pcap Response
```json
{
  "metrics": {
    "accuracy": 0.95,
    "recall": 0.92,
    "f1": 0.94,
    "cm": [TN, FP, FN, TP]
  },
  "flows": [
    {
      "timestamp": 1703001234.567,
      "src_ip": "192.168.1.10",
      "dst_ip": "10.0.0.5",
      "src_port": 4455,
      "dst_port": 80,
      "protocol": 6,
      "prediction": "DDoS",
      "action": "BLOCK",
      "confidence": 0.94,
      "label": "DDoS"
    }
  ]
}
```

### /flows Response
```json
{
  "flows": [...],
  "running": true
}
```

## Testing

### Test PCAP Upload
```bash
# Prepare test files
cp nightmirror.pcap test.pcap
# Upload via web UI at http://127.0.0.1:5000
```

### Test Live Capture

1. Start Mininet:
```bash
sudo mn --topo linear,2 --switch ovsk
```

2. Configure OVS mirror (in Mininet):
```bash
mininet> sh ovs-vsctl -- set bridge s1 mirrors=@m \
  -- --id=@s1-eth1 get port s1-eth1 \
  -- --id=@s1-snoop get port s1-snoop \
  -- --id=@m create mirror name=m0 select-src-port=@s1-eth1 select-dst-port=@s1-eth1 output-port=@s1-snoop
```

3. Generate traffic:
```bash
mininet> h1 iperf -s &
mininet> h2 iperf -c 10.0.0.1 -t 20
```

4. In dashboard: enter "s1-snoop", click START

## Troubleshooting

- **404 on dashboard**: Check Flask is serving at root `/`
- **No flows in live mode**: Verify interface exists (`ip link show s1-snoop`)
- **Classifier errors**: Check 10.100.10.15:8000/predict is accessible
- **Large PCAP uploads**: NGINX configured with 200MB limit
