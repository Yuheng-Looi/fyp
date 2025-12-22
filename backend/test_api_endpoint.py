
import pandas as pd
from fastapi.testclient import TestClient
from infer_server import app
import os

# Create a dummy CSV file for testing
def create_test_csv():
    source_file = "/home/fyp2025/fyp/backend/datasets/Normal_data.csv"
    if not os.path.exists(source_file):
        print(f"Source file {source_file} not found.")
        return None
    
    df = pd.read_csv(source_file, nrows=50)
    test_file = "test_sample.csv"
    df.to_csv(test_file, index=False)
    return test_file

def test_analyze_pcap():
    with TestClient(app) as client:
        csv_file = create_test_csv()
        if not csv_file:
            return

        print(f"Testing with {csv_file}...")
        
        with open(csv_file, "rb") as f:
            response = client.post(
                "/analyze_pcap",
                files={"file": ("test_sample.csv", f, "text/csv")},
                data={"scaler_id": "default", "label_col": "Label", "normal_label": "Normal"}
            )
        
        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print("Keys in response:", data.keys())
            if "metrics" in data:
                print("Metrics:", data["metrics"])
            if "flows" in data:
                print(f"Number of flows: {len(data['flows'])}")
                if len(data['flows']) > 0:
                    print("First flow sample:", data['flows'][0])
        else:
            print("Error:", response.text)

        # Cleanup
        if os.path.exists(csv_file):
            os.remove(csv_file)

if __name__ == "__main__":
    test_analyze_pcap()
