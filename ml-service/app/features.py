import pandas as pd

FEATURES = ["hour", "is_failed", "is_foreign", "failed_5min", "country_change_60min"]


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    # df["timestamp"] = pd.to_datetime(df["timestamp"]) WRONGGGGG
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
    df = df.sort_values("timestamp").reset_index(drop=True)

    df["hour"] = df["timestamp"].dt.hour
    df["is_failed"] = (df["status"] == "failed").astype(int)

    # Foreign = login from a country that isn't the user's most common one
    home = df.groupby("user")["country"].agg(lambda s: s.mode()[0])
    df["is_foreign"] = (df["country"] != df["user"].map(home)).astype(int)

    # Failed attempts by the same user + IP in the trailing 5 minutes
    def failed_window(g):
        s = g.set_index("timestamp")["is_failed"].rolling("5min").sum()
        return pd.Series(s.values, index=g.index)

    df["failed_5min"] = df.groupby(["user", "src_ip"], group_keys=False).apply(failed_window)

    # Country differs from the user's previous event within 60 minutes
    g = df.sort_values(["user", "timestamp"])
    prev_country = g.groupby("user")["country"].shift()
    prev_time = g.groupby("user")["timestamp"].shift()
    minutes = (g["timestamp"] - prev_time).dt.total_seconds() / 60
    df["country_change_60min"] = ((g["country"] != prev_country) & (minutes <= 60)).astype(int)

    return df
