"""Synthetic authentication log generator with injected, labeled anomalies."""
import argparse
import random
from datetime import datetime, timedelta

import pandas as pd

COUNTRIES = {"IN": "103.21", "US": "52.14", "DE": "18.196", "SG": "13.250", "BR": "177.71"}
USERS = [f"user{i:02d}" for i in range(1, 21)]


def rand_ip(country, rng):
    return f"{COUNTRIES[country]}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def event(ts, user, country, status, ip, label=0, atype="none"):
    return {
        "timestamp": ts.isoformat(),
        "user": user,
        "src_ip": ip,
        "country": country,
        "status": status,
        "label": label,
        "anomaly_type": atype,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default="ml-service/data/auth_logs.csv")
    args = p.parse_args()

    rng = random.Random(args.seed)
    start = datetime(2026, 9, 1)
    home = {u: rng.choice(list(COUNTRIES)) for u in USERS}
    rows = []

    # Normal behaviour: office-hours logins from the user's home country
    for d in range(args.days):
        day = start + timedelta(days=d)
        for u in USERS:
            for _ in range(rng.randint(2, 6)):
                ts = day + timedelta(hours=rng.randint(8, 18),
                                     minutes=rng.randint(0, 59),
                                     seconds=rng.randint(0, 59))
                status = "failed" if rng.random() < 0.03 else "success"
                rows.append(event(ts, u, home[u], status, rand_ip(home[u], rng)))

    def random_day_time(h_min, h_max):
        day = start + timedelta(days=rng.randint(0, args.days - 1))
        return day + timedelta(hours=rng.randint(h_min, h_max), minutes=rng.randint(0, 59))

    # Anomaly 1: brute force (burst of failed logins from one foreign IP)
    for _ in range(max(1, args.days // 3)):
        u = rng.choice(USERS)
        ts = random_day_time(0, 23)
        c = rng.choice([x for x in COUNTRIES if x != home[u]])
        ip = rand_ip(c, rng)
        for i in range(rng.randint(30, 80)):
            rows.append(event(ts + timedelta(seconds=i * rng.uniform(1, 3)),
                              u, c, "failed", ip, 1, "brute_force"))

    # Anomaly 2: odd-hour login (1-4 AM)
    for _ in range(args.days):
        u = rng.choice(USERS)
        rows.append(event(random_day_time(1, 4), u, home[u], "success",
                          rand_ip(home[u], rng), 1, "odd_hour"))

    # Anomaly 3: impossible travel (foreign login minutes after a home login)
    for _ in range(max(1, args.days // 3)):
        u = rng.choice(USERS)
        ts = random_day_time(9, 16)
        rows.append(event(ts, u, home[u], "success", rand_ip(home[u], rng)))
        far = rng.choice([x for x in COUNTRIES if x != home[u]])
        rows.append(event(ts + timedelta(minutes=rng.randint(5, 30)), u, far,
                          "success", rand_ip(far, rng), 1, "impossible_travel"))

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} events to {args.out}")
    print(df["anomaly_type"].value_counts())


if __name__ == "__main__":
    main()