import pandas as pd

def main():
    csv_path = "UNSW_NB15_merged_renamed.csv"  # Adjust if your CSV name differs
    
    print(f"Loading {csv_path}...")
    df = pd.read_csv(csv_path)
    print("Shape of dataset:", df.shape)
    
    # 1. Quick overview
    print("\n--- HEAD ---")
    print(df.head(5))
    
    print("\n--- INFO ---")
    print(df.info())

    # 2. Missing value counts
    print("\n--- Missing Values per Column ---")
    print(df.isnull().sum())
    
    # 3. Distribution of label
    print("\n--- Label Distribution ---")
    print(df["label"].value_counts(dropna=False))
    
    # 4. Attack categories (top 10 categories)
    print("\n--- Attack Cat Distribution (top 10) ---")
    print(df["attack_cat"].value_counts(dropna=False).head(10))
    
    # 5. Another categorical example: 'proto', 'service', 'state' (just to see variety)
    print("\n--- Unique Protocols (sample) ---")
    print(df["proto"].unique()[:10])
    
    print("\n--- Unique Services (sample) ---")
    print(df["service"].unique()[:10])
    
    print("\n--- Unique States (sample) ---")
    print(df["state"].unique()[:10])
    
    # 6. Basic stats for numeric columns
    print("\n--- DESCRIBE (numeric columns) ---")
    print(df.describe())

if __name__ == "__main__":
    main()
