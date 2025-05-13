import pandas as pd
import numpy as np

def main():
    csv_path = "UNSW_NB15_cleaned.csv"  # The file from your previous cleaning step
    print(f"Loading {csv_path}...")
    df = pd.read_csv(csv_path)

    # 1) Quick check for any NaNs
    print("\n--- Before final fix ---")
    print("NaN counts:\n", df.isnull().sum())
    print("Shape:", df.shape)

    # 2) Drop rows that have missing sport or dport
    #    It's only ~312 rows total among 2.54 million, so negligible impact.
    df.dropna(subset=["sport", "dport"], inplace=True)
    # Confirm how many rows remain
    print("\nAfter dropping rows with missing sport/dport:")
    print("Shape:", df.shape)
    print("NaN counts:\n", df.isnull().sum())

    # 3) Fill ct_ftp_cmd with 0 for the ~1.4M missing entries
    #    This indicates "non-FTP flow"
    df["ct_ftp_cmd"] = df["ct_ftp_cmd"].fillna(0)

    # 4) Final check
    print("\n--- After filling ct_ftp_cmd = 0 ---")
    print("NaN counts:\n", df.isnull().sum())
    print("Shape:", df.shape)
    
    # 5) Quick sample
    print("\nSample rows:\n", df.head(5))

    # 6) Save final dataset
    df.to_csv("UNSW_NB15_final.csv", index=False)
    print("\nSaved final dataset to 'UNSW_NB15_final.csv'")

if __name__ == "__main__":
    main()