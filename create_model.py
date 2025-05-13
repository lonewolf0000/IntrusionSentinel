import xgboost as xgb
import numpy as np
from sklearn.preprocessing import LabelEncoder
import joblib

def create_model():
    # Create a basic XGBoost model
    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective='binary:logistic',
        random_state=42
    )
    
    # Create dummy data for training
    X = np.random.rand(100, 44)  # 44 features as in the model
    y = np.random.randint(0, 2, 100)  # Binary classification
    
    # Train the model
    model.fit(X, y)
    
    # Save the model
    model.save_model('best_xgb_model.json')
    
    # Create and save label encoders
    proto_encoder = LabelEncoder()
    proto_encoder.fit(['tcp', 'udp', 'icmp', 'other'])
    joblib.dump(proto_encoder, 'proto_label_encoder.joblib')
    
    service_encoder = LabelEncoder()
    service_encoder.fit(['http', 'https', 'dns', 'ssh', 'ftp', 'smtp', 'other'])
    joblib.dump(service_encoder, 'service_label_encoder.joblib')
    
    state_encoder = LabelEncoder()
    state_encoder.fit(['ESTABLISHED', 'CLOSED', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT', 'TIME_WAIT', 'other'])
    joblib.dump(state_encoder, 'state_label_encoder.joblib')

if __name__ == '__main__':
    create_model()
    print("Model and encoders created successfully!") 