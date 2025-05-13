# IntrusionSentinel

IntrusionSentinel is a hybrid Intrusion Detection System (IDS) that combines signature-based and anomaly-based detection methods to provide comprehensive network security monitoring. The system uses machine learning (XGBoost) for anomaly detection and maintains a database of known threat signatures for signature-based detection.

## Features

- **Hybrid Detection**: Combines signature-based and anomaly-based detection methods
- **Real-time Monitoring**: Monitors network traffic in real-time for potential intrusions
- **Machine Learning**: Uses XGBoost for anomaly detection
- **Threat Intelligence**: Maintains databases of known threat IPs and domains
- **Web Dashboard**: Interactive dashboard for monitoring and analyzing security events
- **Logging**: Comprehensive logging of all detected events and system activities

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Required Python packages (install using `pip install -r requirements.txt`):
  - xgboost
  - scikit-learn
  - pandas
  - numpy
  - flask
  - joblib
  - scapy
  - requests

## Installation

1. Clone the repository:
```bash
git clone https://github.com/lonewolf0000/IntrusionSentinel.git
cd IntrusionSentinel
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Download and prepare the dataset:
   - Place your network traffic dataset in the appropriate directory
   - Run the data preprocessing scripts if needed

## Usage

### Training the Model

1. Train the XGBoost model:
```bash
python train_xgboost.py
```

2. Create the model:
```bash
python create_model.py
```

### Running the IDS

1. Start the hybrid IDS:
```bash
python hybrid_ids.py
```

2. Access the web dashboard:
   - Open your web browser
   - Navigate to `http://localhost:5000`

### Signature-based Detection

The signature-based detection system uses:
- `local_threat_ips.txt`: Database of known malicious IP addresses
- `local_threat_domains.txt`: Database of known malicious domains
- `signature_ids.py`: Implementation of signature-based detection

### Anomaly-based Detection

The anomaly-based detection system:
- Uses XGBoost for machine learning-based detection
- Trained on normal network traffic patterns
- Detects deviations from normal behavior

## Project Structure

```
IntrusionSentinel/
├── hybrid_ids.py           # Main hybrid IDS implementation
├── signature_ids.py        # Signature-based detection
├── anomaly_ids.py          # Anomaly-based detection
├── train_xgboost.py        # Model training script
├── create_model.py         # Model creation script
├── dashboard.py            # Web dashboard implementation
├── static/                 # Static files for web dashboard
│   ├── css/
│   └── js/
├── templates/              # HTML templates
│   ├── index.html
│   └── dashboard.html
├── best_xgb_model.json     # Trained XGBoost model
├── local_threat_ips.txt    # Known malicious IPs
├── local_threat_domains.txt # Known malicious domains
└── *.joblib               # Encoder files for categorical variables
```

## Logging

The system maintains two main log files:
- `hybrid_ids.log`: Logs from the hybrid IDS system
- `intrusion_sentinel.log`: General system logs

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- UNSW-NB15 dataset for training data
- XGBoost library for machine learning capabilities
- Flask for web dashboard implementation 