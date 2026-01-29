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

## API Endpoints

The `infer_server.py` provides the following REST API endpoints for the Frontend and external tools:

### Inference & Analysis
- **`POST /predict`**
  - **Description**: Real-time prediction for a single network flow.
  - **Input**: flow features (JSON).
  - **Output**: Anomaly flags, attack probability, and recommended action (ALLOW, LOG, BLOCK).

- **`POST /analyze_pcap`**
  - **Description**: Batch analysis of a CSV file (converted from PCAP).
  - **Input**: CSV file upload.
  - **Output**: Detailed metrics (Accuracy, F1), list of flows with predictions, and summary statistics.

### Model & Scaler Management
- **`GET /models`**
  - **Description**: Lists all available trained models (XGBoost, GNN, Isolation Forest).
  
- **`GET /scalers`**
  - **Description**: Lists all available data scalers.

- **`POST /refit_scaler`**
  - **Description**: Creates a new scaler based on provided benign traffic data.
  - **Input**: CSV file with benign traffic.

- **`GET /scaler_stats`**
  - **Description**: Retrieves statistical properties (e.g., median, IQR) of a scaler for drift detection visualization.

### Training System
- **`POST /retrain/{model_type}`**
  - **Description**: Initiates a background training job for a specific model type (`xgb`, `gnn`, or `isolation_forest`).
  - **Input**: Training dataset (CSV) and hyperparameters.
  - **Output**: Job ID to track progress.

- **`GET /retrain/status/{job_id}`**
  - **Description**: Checks the status of a running or completed training job.

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
