# Flow Dashboard Frontend

This folder hosts the lightweight Flask + vanilla JS dashboard for offline CSV/PCAP analysis and live traffic capture.

## 1. Python Environment

```bash
cd /home/yuheng/fyp/frontend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Keep `venv/` activated while running commands below. Use `deactivate` to exit.

## 2. Flask API + Dashboard

Start the Flask server (serves `dashboard.html` and all APIs on port 5000):

```bash
source venv/bin/activate
python server.py
```

Nginx can proxy `http://<host>/` to this service. For local testing hit `http://127.0.0.1:5000/dashboard.html`.

## 3. Live Traffic Helper (Mininet)

`live.py` builds a small Mininet topology, mirrors `s1` traffic to an internal monitor interface, and generates pings/iperf.

> ⚠ Requires root privileges because it manipulates Mininet/OVS.

```bash
source venv/bin/activate
sudo python live.py \
  --monitor-iface s1-snoop \
  --ping-count 5 \
  --iperf-duration 10
```

In the dashboard’s *Live* tab, choose the mirrored interface (`s1-snoop`) and click START to classify flows in real time.

## 4. Offline Utilities

- `cic_extractor.py`, `edge_extractor.py`, `flow_extractor.py` provide PCAP/packet feature extraction helpers.
- `test_csv_analysis.py` contains lightweight regression tests for CSV ingestion.

Run any script with the venv active, e.g.:

```bash
source venv/bin/activate
python test_csv_analysis.py
```

## 5. System Services

- `flow-dashboard.service.sample`: sample systemd unit that runs `server.py` via `venv`.
- `nginx.flow-dashboard.sample`: Nginx site config that serves `dashboard.html` and proxies APIs to `localhost:5000`.

Copy these into `/etc/systemd/system/` or `/etc/nginx/sites-available/` as needed and reload the respective services.

## 6. Assets & Uploads

- CSV/PCAP uploads land under `uploads/` (auto-created by `server.py`).
- Large capture files are ignored by git; ensure you have enough disk space.

## 7. Troubleshooting

- **Bad Gateway (502)**: verify `python server.py` is running; check Nginx proxy in `nginx.flow-dashboard.sample`.
- **live.py permissions**: always run with `sudo` after activating the venv.
- **Missing deps**: re-run `pip install -r requirements.txt` inside `venv`.
