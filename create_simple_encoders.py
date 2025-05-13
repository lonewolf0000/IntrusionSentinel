import joblib
from sklearn.preprocessing import LabelEncoder

def main():
    # Create simple encoder for 'proto'
    proto_encoder = LabelEncoder()
    proto_values = ['tcp', 'udp', 'icmp', 'other', '-', 'unknown']
    proto_encoder.fit(proto_values)
    joblib.dump(proto_encoder, 'proto_label_encoder.joblib')
    print(f"Created proto_label_encoder.joblib with {len(proto_values)} values")
    
    # Create simple encoder for 'state'
    state_encoder = LabelEncoder()
    state_values = ['FIN', 'CON', 'REQ', 'URH', 'ECO', 'ECR', 'INT', 'PAR', 'RST', 
                     'MAS', 'TST', 'ACC', 'CLO', 'TXD', 'EST', 'OTH', '-', 'unknown']
    state_encoder.fit(state_values)
    joblib.dump(state_encoder, 'state_label_encoder.joblib')
    print(f"Created state_label_encoder.joblib with {len(state_values)} values")
    
    # Create simple encoder for 'service'
    service_encoder = LabelEncoder()
    service_values = ['http', 'ftp', 'ftp-data', 'smtp', 'dns', 'ssh', 'irc', 'ssl', 
                       'dhcp', 'pop3', 'snmp', 'https', 'radius', 'telnet', 'icmp', 
                       '-', 'unknown']
    service_encoder.fit(service_values)
    joblib.dump(service_encoder, 'service_label_encoder.joblib')
    print(f"Created service_label_encoder.joblib with {len(service_values)} values")

if __name__ == "__main__":
    main()