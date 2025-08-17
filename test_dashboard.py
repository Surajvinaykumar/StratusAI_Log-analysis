import requests
import json

def test_dashboard():
    """Test the log anomaly detection dashboard"""
    
    # Test health endpoint
    print("Testing health endpoint...")
    try:
        response = requests.get('http://localhost:5000/health')
        print(f"Health check: {response.json()}")
    except Exception as e:
        print(f"Health check failed: {e}")
        return
    
    # Test file upload
    print("\nTesting file upload...")
    try:
        with open('sample_logs.txt', 'rb') as f:
            files = {'file': f}
            response = requests.post('http://localhost:5000/upload', files=files)
        
        if response.status_code == 200:
            result = response.json()
            print(f"Upload successful!")
            print(f"Total entries: {result['total_entries']}")
            print(f"Anomalies detected: {result['anomaly_count']}")
            print(f"Anomaly percentage: {result['anomaly_percentage']:.2f}%")
            
            print("\nAnomalies found:")
            for anomaly in result['anomalies']:
                print(f"  Line {anomaly['line_number']}: {anomaly['message']}")
        else:
            print(f"Upload failed with status code {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"File upload test failed: {e}")

if __name__ == "__main__":
    test_dashboard()
