import argparse
import time

import pandas as pd
import requests

p = argparse.ArgumentParser()
p.add_argument("--csv", default="ml-service/data/auth_logs.csv")
p.add_argument("--url", default="http://127.0.0.1:8000/predict")
p.add_argument("--limit", type=int, default=None)
args = p.parse_args()

df = pd.read_csv(args.csv)
if args.limit:
    df = df.head(args.limit)

session = requests.Session()
sent = flagged = indexed = failed = 0
start = time.time()

for row in df.itertuples():
    payload = {
        "timestamp": row.timestamp,
        "user": row.user,
        "src_ip": row.src_ip,
        "country": row.country,
        "status": row.status,
    }
    r = session.post(args.url, json=payload, timeout=10)
    if r.ok:
        body = r.json()
        sent += 1
        flagged += body["anomaly"]
        indexed += body["indexed"]
    else:
        failed += 1
    if (sent + failed) % 250 == 0:
        print(f"{sent + failed}/{len(df)} processed...")

print(f"Done in {time.time() - start:.1f}s: sent={sent}, flagged={flagged}, "
      f"indexed={indexed}, failed={failed}")