# Backend - Anomaly Detection System

This repository contains the backend code for the Anomaly Detection System. It hosts the inference server, manages machine learning models, and handles data processing tasks.

## Project Structure

```
backend/
├── infer_server.py         # Main entry point to start the inference server
├── fypenv/                 # Pre-configured Virtual Environment
├── requirements.txt        # Python dependencies
├── models/                 # Saved ML/DL models (GNN, XGBoost, etc.)
├── datasets/               # Reference datasets
├── scalers/                # Data scalers for preprocessing
├── *_utils.py              # Utility scripts for data, models, and EDAs
└── output/                 # Output directory for predictions
```

## Setup & Installation

You can either use the provided virtual environment or create a new one.

### Prerequisites
- Python 3.12 (Recommended)
- CUDA-compatible GPU (for GNN models)

### Option 1: Use Existing Environment (Quick Start)
Activate the pre-bundled virtual environment:

```bash
source fypenv/bin/activate
```

### Option 2: Create a New Virtual Environment (Optional)
If you prefer to set up a clean environment:

1. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   ```

2. **Activate the environment:**
   ```bash
   source venv/bin/activate
   # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

To start the backend server, simply run:

```bash
python infer_server.py
```

The server will start and listen for requests from the frontend or direct API calls.

## Frontend

For the user interface and dashboard setup, please refer to the **Frontend README** located at:
`../frontend/README.md`

---

## System Specifications

The current system is deployed and tested on the following specifications:

- **OS**: Linux
- **CPU**: 11th Gen Intel(R) Core(TM) i9-11900K @ 3.50GHz (16 Logical Cores)
- **RAM**: ~64 GB
- **GPU**: NVIDIA GeForce RTX 3080 Ti (12GB VRAM)
- **CUDA Version**: 13.0
