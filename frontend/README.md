# Frontend Dashboard

This directory contains the frontend component of the network anomaly detection system. It provides a web interface for monitoring traffic, visualizing network topology, and displaying detection results from the backend.

## Project Structure

- **server.py**: The main entry point. A Flask server that handles:
  - Network topology management (Mininet/OVS interactions).
  - Traffic flow monitoring and feature extraction.
  - Communication with the ML backend for anomaly prediction.
  - Serving the web dashboard.
- **cic_extractor.py**: Utility for extracting network flow features (CICFlowMeter compatible).
- **dashboard.html**: The web-based user interface.
- **requirements.txt**: Python dependencies.
- **attack_generator.py**: Script to simulate network attacks.
- **live_test.py**: Integration testing script.

## System Requirements

- **Operating System**: Linux (Ubuntu 20.04 LTS or newer recommended).
  - *Note: This application requires Linux network namespaces and Open vSwitch, so it will not run natively on Windows or macOS.*
- **Python**: 3.8 or higher.
- **Privileges**: Root/sudo access is required to manage network interfaces and OVS bridges.

## Backend Configuration

The frontend is configured to send traffic data to a Machine Learning backend.
- **Backend IP**: `10.100.10.15`
- **Backend Endpoint**: `http://10.100.10.15:8000/predict`
- **Backend Documentation**: Please refer to the README in the `../backend` directory (to be written).

## Installation

1. **Create a Virtual Environment** (Optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

To start the web server and network monitoring system:

1. Ensure your virtual environment is activated:
   ```bash
   source venv/bin/activate
   ```

2. Run the server with `sudo`:
   ```bash
   sudo ./venv/bin/python3 server.py
   ```
   *Note: Using `sudo` with the absolute path to the venv python ensure it uses the installed dependencies while having root privileges.* 
   *Alternatively, if you are in a root shell with the venv activated, just `python3 server.py` works.*

Once running, access the dashboard in your web browser at:
`http://localhost:5000/dashboard.html` (or the IP address of this machine).

## Reference System Specifications

The system has been tested and verified on the following hardware/software configuration:

- **OS**: Ubuntu 24.04.3 LTS (Noble Numbat)
- **Kernel/Arch**: x86_64
- **CPU**: Intel(R) Xeon(R) CPU D-1518 @ 2.20GHz (8 cores)
- **RAM**: ~32GB (31Gi)
- **Python Version**: 3.12.3
- **Disk**: 232GB Storage
