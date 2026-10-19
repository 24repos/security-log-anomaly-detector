import json
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report

from features import FEATURES, build_features

df = build_features(pd.read_csv("ml-service/data/auth_logs.csv"))

model = IsolationForest(n_estimators=200, contamination=0.18, random_state=42)
model.fit(df[FEATURES])  # unsupervised algo so labels are NOT used for training. IF learns from features to know what unusual looks like.

df["pred"] = (model.predict(df[FEATURES]) == -1).astype(int)

print(classification_report(df["label"], df["pred"], target_names=["normal", "anomaly"]))
print("Detection rate per anomaly type:")
print(df.groupby("anomaly_type")["pred"].mean())

joblib.dump(model, "ml-service/models/isolation_forest.joblib")

home = df.groupby("user")["country"].agg(lambda s: s.mode()[0]).to_dict()
with open("ml-service/models/home_countries.json", "w") as f:
    json.dump(home, f)

print("Model saved.")