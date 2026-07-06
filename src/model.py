import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

def load_raw_data(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.dropna(subset=['Attack Type'])
    df['Attack Type'] = df['Attack Type'].str.strip()
    severity_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
    df['Severity Score'] = df['Severity Level'].str.capitalize().str.strip().map(severity_map).fillna(0).astype(int)
    print(f"[✓] Dataset brut chargé : {df.shape[0]} lignes, {df.shape[1]} colonnes")
    return df

def encode_features(df: pd.DataFrame):
    encoders = {}
    cat_cols = [
        'Protocol', 'Malware Indicators', 'Action Taken',
        'Traffic Type', 'Packet Type', 'Attack Signature',
        'Network Segment', 'Log Source'
    ]
    for col in cat_cols:
        le = LabelEncoder()
        df[f'{col}_enc'] = le.fit_transform(df[col].astype(str))
        encoders[col] = le

    le_target = LabelEncoder()
    df['Target_enc'] = le_target.fit_transform(df['Attack Type'].astype(str))
    encoders['target'] = le_target

    print(f"[✓] Classes détectées : {list(le_target.classes_)}")
    return df, encoders

def prepare_xy(df: pd.DataFrame):
    X = df[[
        'Source Port', 'Destination Port',
        'Packet Length', 'Anomaly Scores', 'Severity Score',
        'Protocol_enc', 'Malware Indicators_enc',
        'Action Taken_enc', 'Traffic Type_enc',
        'Packet Type_enc', 'Attack Signature_enc',
        'Network Segment_enc', 'Log Source_enc'
    ]]
    y = df['Target_enc']
    return X, y

def train_model(X_train, y_train):
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    print("[✓] Modèle Random Forest entraîné")
    return model

def evaluate_model(model, X_test, y_test, encoders):
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[✓] Accuracy : {acc:.4f}")
    print("\n--- Rapport de classification ---")
    print(classification_report(
        y_test, y_pred,
        target_names=encoders['target'].classes_
    ))
    feature_names = [
        'Source Port', 'Destination Port',
        'Packet Length', 'Anomaly Scores', 'Severity Score',
        'Protocol', 'Malware Indicators', 'Action Taken',
        'Traffic Type', 'Packet Type', 'Attack Signature',
        'Network Segment', 'Log Source'
    ]
    importances = pd.Series(
        model.feature_importances_, index=feature_names
    ).sort_values(ascending=False)
    print("\n--- Feature Importance ---")
    print(importances)

def save_model(model, encoders, base_path: str):
    os.makedirs(os.path.join(base_path, "models"), exist_ok=True)
    joblib.dump(model, os.path.join(base_path, "models/rf_model.pkl"))
    joblib.dump(encoders, os.path.join(base_path, "models/encoders.pkl"))
    print("\n[✓] Modèle et encoders sauvegardés dans models/")

if __name__ == "__main__":
    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    raw_path = os.path.join(BASE, "data/raw/cyber_attacks/cybersecurity_attacks.csv")
    df = load_raw_data(raw_path)
    df, encoders = encode_features(df)
    X, y = prepare_xy(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[✓] Train : {X_train.shape[0]} | Test : {X_test.shape[0]}")

    model = train_model(X_train, y_train)
    evaluate_model(model, X_test, y_test, encoders)
    save_model(model, encoders, BASE)
