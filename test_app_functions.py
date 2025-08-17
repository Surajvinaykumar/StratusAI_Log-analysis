import sys
import os
import pandas as pd
import numpy as np

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import functions from app.py
from app import parse_syslog_line, extract_features, detect_anomalies

def test_log_parsing():
    """Test log parsing functionality"""
    print("Testing log parsing...")
    
    # Test RFC 3164 format
    line1 = "<13>Oct 11 22:14:15 server1 sshd[12345]: Connection closed"
    parsed1 = parse_syslog_line(line1)
    print(f"Parsed RFC 3164 format: {parsed1}")
    
    # Test alternative format
    line2 = "2023-10-11T22:14:15 server1 sshd: Connection closed"
    parsed2 = parse_syslog_line(line2)
    print(f"Parsed alternative format: {parsed2}")
    
    # Test invalid format
    line3 = "This is not a valid syslog format"
    parsed3 = parse_syslog_line(line3)
    print(f"Parsed invalid format: {parsed3}")

def test_feature_extraction():
    """Test feature extraction functionality"""
    print("\nTesting feature extraction...")
    
    # Sample log entries
    log_entries = [
        {
            'line_number': 1,
            'priority': '13',
            'timestamp': 'Oct 11 22:14:15',
            'hostname': 'server1',
            'tag': 'sshd[12345]',
            'message': 'Connection closed'
        },
        {
            'line_number': 2,
            'priority': '14',
            'timestamp': 'Oct 11 22:14:16',
            'hostname': 'server1',
            'tag': 'sshd[12346]',
            'message': 'Invalid user admin from 192.168.1.100'
        }
    ]
    
    features = extract_features(log_entries)
    print(f"Extracted features shape: {features.shape}")
    print(f"Sample features: {features[:2]}")

def test_anomaly_detection():
    """Test anomaly detection functionality"""
    print("\nTesting anomaly detection...")
    
    # Create sample features
    features = np.array([
        [10.0, 100.0, 50.0],
        [20.0, 100.0, 50.0],
        [15.0, 100.0, 50.0],
        [30.0, 100.0, 50.0],
        [12.0, 100.0, 50.0]
    ], dtype=np.float32)
    
    results = detect_anomalies(features)
    print(f"Anomaly detection results: {results}")

def test_with_sample_logs():
    """Test with actual sample logs"""
    print("\nTesting with sample logs...")
    
    # Read sample logs
    log_entries = []
    with open('sample_logs.txt', 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:  # Skip empty lines
                parsed = parse_syslog_line(line)
                parsed['line_number'] = line_num
                log_entries.append(parsed)
    
    print(f"Parsed {len(log_entries)} log entries")
    
    # Extract features
    features = extract_features(log_entries)
    print(f"Extracted features shape: {features.shape}")
    
    # Run anomaly detection
    results = detect_anomalies(features)
    print(f"Anomaly detection results:")
    print(f"  Total entries: {results['count']}")
    print(f"  Anomalies detected: {results['anomaly_count']}")
    
    # Show some anomalies
    if results['anomaly_count'] > 0:
        print(f"  Anomaly percentage: {(results['anomaly_count'] / results['count']) * 100:.2f}%")
        print("  Sample anomalies:")
        for i, (is_anomaly, score) in enumerate(zip(results['anomalies'][:3], results['anomaly_scores'][:3])):
            if is_anomaly:
                print(f"    Entry {i}: Score {score:.3f}")

if __name__ == "__main__":
    test_log_parsing()
    test_feature_extraction()
    test_anomaly_detection()
    test_with_sample_logs()
