import pandas as pd
import xgboost as xgb
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

def main():
    # 1) Load the train, val, test splits (already preprocessed & encoded)
    print("Loading train/val/test CSVs...")
    df_train = pd.read_csv("UNSW_NB15_train.csv")
    df_val = pd.read_csv("UNSW_NB15_val.csv")
    df_test = pd.read_csv("UNSW_NB15_test.csv")

    # Separate features & labels
    X_train = df_train.drop("label", axis=1)
    y_train = df_train["label"]
    
    X_val = df_val.drop("label", axis=1)
    y_val = df_val["label"]
    
    X_test = df_test.drop("label", axis=1)
    y_test = df_test["label"]

    print("Train shape:", X_train.shape)
    print("Val shape:", X_val.shape)
    print("Test shape:", X_test.shape)

    # 2) Convert to XGBoost DMatrix
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dval = xgb.DMatrix(X_val, label=y_val)
    dtest = xgb.DMatrix(X_test, label=y_test)

    # 3) XGBoost parameters for GPU training + decent hyperparameters
    params = {
        "objective": "binary:logistic",
        "eval_metric": "auc",
        "tree_method": "gpu_hist",   # Note: in XGBoost 2.0+, recommended is "hist" + "device": "cuda"
        "predictor": "gpu_predictor",

        # Some typical hyperparameters
        "max_depth": 8,         # Depth of each tree
        "learning_rate": 0.1,   # Step size shrinkage
        "subsample": 0.8,       # Row sampling
        "colsample_bytree": 0.8 # Feature sampling
        # Optionally add "lambda", "alpha" for regularization if needed
    }

    # 4) Train with early stopping on validation set
    evals = [(dtrain, "train"), (dval, "val")]
    print("\nTraining XGBoost on GPU with the following params:")
    for k, v in params.items():
        print(f"{k} = {v}")

    bst = xgb.train(
        params,
        dtrain,
        num_boost_round=1000,       # up to 1000 iterations
        evals=evals,
        early_stopping_rounds=30,   # stop if val AUC doesn't improve for 30 rounds
        verbose_eval=10            # print updates every 10 rounds
    )

    best_iter = bst.best_iteration
    print(f"\nBest iteration: {best_iter}  Best AUC on val: {bst.best_score:.4f}")

    # 5) Evaluate on the test set, using the best iteration
    print("\nEvaluating on test set...")
    preds_proba = bst.predict(dtest, iteration_range=(0, best_iter+1))

    # Convert probability preds to binary
    preds = [1 if p >= 0.5 else 0 for p in preds_proba]

    acc = accuracy_score(y_test, preds)
    prec = precision_score(y_test, preds)
    rec = recall_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    auc = roc_auc_score(y_test, preds_proba)

    print("\nFinal Test Metrics:")
    print(f"Accuracy:   {acc:.4f}")
    print(f"Precision:  {prec:.4f}")
    print(f"Recall:     {rec:.4f}")
    print(f"F1-score:   {f1:.4f}")
    print(f"ROC-AUC:    {auc:.4f}")

    # 6) Save the trained model to disk
    bst.save_model("best_xgb_model.json")
    print("Model saved as best_xgb_model.json")

if __name__ == "__main__":
    main()