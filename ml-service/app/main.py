import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel

from features import FEATURES

MODEL_DIR = Path(__file__).resolve().parents[1] / "models"
model = joblib.load(MODEL_DIR / "isolation_forest.joblib")
home_country = json.loads((MODEL_DIR / "home_countries.json").read_text())

# Recent events per user, used for the time-window features
history = defaultdict(deque)

app = FastAPI(title="Security Log Anomaly Detector - ML Service")


class AuthEvent(BaseModel):
    timestamp: datetime
    user: str
    src_ip: str
    country: str
    status: str  # "success" or "failed"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/predict")
def predict(e: AuthEvent):
    ts = e.timestamp.replace(tzinfo=None)
    events = history[e.user]

    # Keep only the last 60 minutes of history for this user
    while events and ts - events[0]["ts"] > timedelta(minutes=60):
        events.popleft()

    is_failed = int(e.status == "failed")
    is_foreign = int(e.country != home_country.get(e.user, e.country))

    failed_5min = is_failed + sum(
        1 for p in events
        if p["ip"] == e.src_ip and p["failed"] and ts - p["ts"] <= timedelta(minutes=5)
    )
    country_change = int(bool(events) and events[-1]["country"] != e.country)

    events.append({"ts": ts, "ip": e.src_ip, "country": e.country, "failed": is_failed})

    row = pd.DataFrame(
        [[ts.hour, is_failed, is_foreign, failed_5min, country_change]], columns=FEATURES
    )
    return {
        "anomaly": bool(model.predict(row)[0] == -1),
        "score": float(model.decision_function(row)[0]),  # lower = more anomalous
        "features": row.iloc[0].to_dict(),
    }