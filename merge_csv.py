import pandas as pd

def main():
    # 1) Define the file paths for your four CSVs
    files = [
        "UNSW-NB15_1.csv",
        "UNSW-NB15_2.csv",
        "UNSW-NB15_3.csv",
        "UNSW-NB15_4.csv"
    ]
    
    # 2) Read each file with comma delimiter, skipping bad lines
    dfs = []
    for f in files:
        print(f"Reading {f} (comma-delimited, skipping bad lines)...")
        df_temp = pd.read_csv(
            f,
            sep=",",
            header=None,
            engine="python",
            on_bad_lines="skip"
        )
        print(f" -> Shape: {df_temp.shape}")
        dfs.append(df_temp)

    # 3) Concatenate into one DataFrame
    print("Concatenating all dataframes...")
    df_full = pd.concat(dfs, ignore_index=True)
    print("Final shape of df_full:", df_full.shape)

    # 4) Rename columns to standard names
    # Adjust the names if your official features CSV says something slightly different.
    col_names = [
        "srcip", "sport", "dstip", "dport", "proto", "state", "dur",
        "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "service",
        "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb",
        "dtcpb", "Smeansz", "Dmeansz", "trans_depth", "res_bdy_len",
        "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt",
        "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
        "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src",
        "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", 
        "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
        "attack_cat", "label"
    ]
    
    if len(col_names) != df_full.shape[1]:
        print("[WARNING] The column name list has a different length than df_full columns!")
        print(f"df_full has {df_full.shape[1]} columns, col_names has {len(col_names)}")
    else:
        df_full.columns = col_names
        print("Columns renamed successfully.")

    # 5) Quick checks
    print("\nFirst 5 rows after renaming:")
    print(df_full.head(5))

    # Print how many unique values in label
    print("\nLabel distribution:")
    print(df_full["label"].value_counts(dropna=False))

    # Print sample of attack_cat
    print("\nUnique attack_cat values (sample):")
    print(df_full["attack_cat"].unique()[:10])

    # 6) (Optional) Save to a new CSV so we don’t have to merge every time
    df_full.to_csv("UNSW_NB15_merged_renamed.csv", index=False)
    print("Saved merged dataset to 'UNSW_NB15_merged_renamed.csv'")

if __name__ == "__main__":
    main()