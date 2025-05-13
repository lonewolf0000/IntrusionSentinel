import pandas as pd
import xgboost as xgb
import numpy as np

def main():
    # 1) Load the saved model
    print("Loading the XGBoost model from 'best_xgb_model.json'...")
    bst = xgb.Booster()
    bst.load_model("best_xgb_model.json")
    print("Model loaded successfully!")
    
    # 2) Create a sample input from UNSW_NB15_test.csv
    # Use double brackets to keep the sample as a DataFrame, preserving column names.
    df_test = pd.read_csv("UNSW_NB15_test.csv")
    sample = df_test.drop("label", axis=1).iloc[[0]]
    print("\nSample input:")
    print(sample)
    
    # 3) Convert the sample into an XGBoost DMatrix
    dsample = xgb.DMatrix(sample)
    
    # 4) Predict using the loaded model
    pred_proba = bst.predict(dsample)
    pred = 1 if pred_proba[0] >= 0.5 else 0
    print("\nPredicted probability:", pred_proba[0])
    print("Predicted label:", pred)

if __name__ == "__main__":
    main()