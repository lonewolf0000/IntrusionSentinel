import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

def main():
    csv_path = "UNSW_NB15_final.csv"
    print(f"Loading {csv_path}...")
    df = pd.read_csv(csv_path)

    print("\nInitial shape:", df.shape)
    print("Sample columns:", df.columns.tolist()[:10], "...")

    # 1) Fill attack_cat NaN => "Normal"
    df["attack_cat"] = df["attack_cat"].fillna("Normal")
    
    # 2) Encode proto, state, service with LabelEncoder
    #    If you want, you can also encode attack_cat for multiclass tasks
    cat_cols = ["proto", "state", "service"]
    # If you prefer to do multi-class classification, also do: cat_cols.append("attack_cat")
    
    for col in cat_cols:
        # Convert to str in case there's any leftover numeric or NaN
        df[col] = df[col].astype(str)
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        print(f"{col}: encoded {len(le.classes_)} unique values")

    # 3) If you’re doing purely binary classification (label=0 or 1),
    #    we typically drop attack_cat or keep it for analysis only.
    #    Let’s assume we drop it from features:
    X = df.drop(["attack_cat","label"], axis=1)
    y = df["label"]

    print("\nFinal feature shape:", X.shape)
    print("Label distribution:\n", y.value_counts())

    # 4) Train/Val/Test split => 80/10/10
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    # Now we have 80% in train, 20% in X_temp
    # Let’s do a 50/50 split on X_temp => 10% val, 10% test
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )

    print("\nSplit shapes:")
    print("Train:", X_train.shape, y_train.shape)
    print("Val:", X_val.shape, y_val.shape)
    print("Test:", X_test.shape, y_test.shape)

    # 5) (Optional) Save these splits to separate CSVs for future quick loading
    X_train["label"] = y_train
    X_val["label"] = y_val
    X_test["label"] = y_test

    X_train.to_csv("UNSW_NB15_train.csv", index=False)
    X_val.to_csv("UNSW_NB15_val.csv", index=False)
    X_test.to_csv("UNSW_NB15_test.csv", index=False)

    print("\nSaved splits to:")
    print(" -> UNSW_NB15_train.csv")
    print(" -> UNSW_NB15_val.csv")
    print(" -> UNSW_NB15_test.csv")

if __name__ == "__main__":
    main()