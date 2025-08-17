# Log File Anomaly Detection Dashboard

A professional end-to-end dashboard for detecting anomalies in log files using machine learning.

## Features

- Secure file upload API for syslog files
- Real-time anomaly detection using PyTorch model
- Interactive dashboard with visualizations
- Threat distribution pie chart
- Anomaly trend analysis
- Detailed anomaly listing
- Responsive and user-friendly interface

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone or download this repository
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the Flask application:
   ```bash
   python app.py
   ```

2. Open your web browser and navigate to `http://localhost:5000`

3. Upload a syslog file using the interface:
   - Drag and drop a file or click "Browse Files"
   - Supported formats: .log, .txt
   - Maximum file size: 16MB

4. View the anomaly detection results:
   - Summary statistics
   - Threat distribution visualization
   - Anomaly trend analysis
   - Detailed anomaly listing

## API Endpoints

- `GET /` - Serve the main dashboard
- `POST /upload` - Upload and analyze a log file
- `GET /health` - Health check endpoint

## Log File Format

The system supports standard syslog formats:

### RFC 3164 Format
```
<priority>timestamp hostname tag: message
<13>Oct 11 22:14:15 server1 sshd[12345]: Connection closed
```

### Alternative Format
```
timestamp hostname tag: message
2023-10-11T22:14:15 server1 sshd: Connection closed
```

## Security Features

- File type validation
- Secure filename handling
- File size limitations
- Error handling and logging

## Model Integration

The dashboard uses `model_scripted.pt` for anomaly detection. The model is loaded at startup and used for inference on uploaded log files.

## Customization

You can customize the dashboard by modifying:
- `templates/index.html` - Frontend interface
- `app.py` - Backend logic and API endpoints
- CSS styles in the HTML template

## Troubleshooting

If you encounter issues:
1. Ensure all requirements are installed
2. Check that the model files are in the correct location
3. Verify the log file format matches the supported formats
4. Check the console for error messages

## License

This project is licensed under the MIT License.
