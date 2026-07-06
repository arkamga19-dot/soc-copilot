import pandas as pd
import json
import os

def load_alerts(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    print(f"[✓] Alertes chargées : {df.shape[0]} lignes, {df.shape[1]} colonnes")
    return df

def clean_alerts(df: pd.DataFrame) -> pd.DataFrame:
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    df = df.dropna(subset=['Attack Type'])
    df['Protocol'] = df['Protocol'].str.upper().str.strip()
    df['Severity Level'] = df['Severity Level'].str.capitalize().str.strip()
    df['Attack Type'] = df['Attack Type'].str.strip()
    severity_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
    df['Severity Score'] = df['Severity Level'].map(severity_map).fillna(0).astype(int)
    print(f"[✓] Après nettoyage : {df.shape[0]} lignes")
    print(f"\n--- Distribution Attack Type ---\n{df['Attack Type'].value_counts()}")
    print(f"\n--- Distribution Severity Level ---\n{df['Severity Level'].value_counts()}")
    return df

def select_features(df: pd.DataFrame) -> pd.DataFrame:
    features = [
        'Source Port', 'Destination Port', 'Protocol',
        'Anomaly Scores', 'Severity Score', 'Malware Indicators',
        'Action Taken', 'Attack Type'
    ]
    return df[features].copy()

def load_playbooks(path: str) -> list:
    playbooks = []
    errors = 0
    with open(path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                playbooks.append(json.loads(line))
            except json.JSONDecodeError as e:
                errors += 1
                print(f"[!] Ligne {i+1} ignorée : {e}")
    print(f"[✓] Playbooks chargés : {len(playbooks)} entrées ({errors} erreurs ignorées)")
    if playbooks:
        print(f"[✓] Clés disponibles : {list(playbooks[0].keys())}")
    return playbooks

if __name__ == "__main__":
    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    alerts_path = os.path.join(BASE, "data/raw/cyber_attacks/cybersecurity_attacks.csv")
    df = load_alerts(alerts_path)
    df = clean_alerts(df)
    df = select_features(df)
    df.to_csv(os.path.join(BASE, "data/processed/alerts_clean.csv"), index=False)
    print(f"\n[✓] Dataset nettoyé sauvegardé dans data/processed/alerts_clean.csv")

    playbooks_path = os.path.join(BASE, "data/raw/playbooks/incident_response_playbook_dataset.jsonl")
    playbooks = load_playbooks(playbooks_path)
