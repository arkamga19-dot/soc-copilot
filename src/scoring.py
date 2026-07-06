import pandas as pd
import os

SEVERITY_WEIGHTS = {'Critical': 100, 'High': 75, 'Medium': 50, 'Low': 25}

def compute_priority_score(row: pd.Series) -> dict:
    score = 0
    reasons = []

    # 1. Score de base depuis la sévérité
    sev = str(row.get('Severity Level', 'Low')).capitalize().strip()
    base = SEVERITY_WEIGHTS.get(sev, 25)
    score += base
    reasons.append(f"Sévérité {sev} (+{base})")

    # 2. IoC détecté
    malware = str(row.get('Malware Indicators', '')).strip()
    if malware == 'IoC Detected':
        score += 30
        reasons.append("IoC Detected (+30)")

    # 3. Action = Ignored (alerte ignorée = plus dangereux que bloquée)
    action = str(row.get('Action Taken', '')).strip()
    if action == 'Ignored':
        score += 20
        reasons.append("Alerte ignorée (+20)")
    elif action == 'Logged':
        score += 10
        reasons.append("Alerte loggée seulement (+10)")

    # 4. Anomaly Score élevé (> 75e percentile = 0.75)
    anomaly = float(row.get('Anomaly Scores', 0))
    if anomaly > 0.75:
        score += 15
        reasons.append(f"Anomaly Score élevé {anomaly:.2f} (+15)")

    # Niveau final
    if score >= 120:
        level = 'CRITIQUE'
    elif score >= 85:
        level = 'HAUTE'
    elif score >= 55:
        level = 'MOYENNE'
    else:
        level = 'FAIBLE'

    return {
        'priority_score': score,
        'priority_level': level,
        'reasons': ' | '.join(reasons)
    }

def score_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    results = df.apply(compute_priority_score, axis=1, result_type='expand')
    df = pd.concat([df, results], axis=1)
    print("[✓] Scoring terminé")
    print("\n--- Distribution priorités ---")
    print(df['priority_level'].value_counts())
    print("\n--- Score moyen par Attack Type ---")
    print(df.groupby('Attack Type')['priority_score'].mean().round(2))
    return df

if __name__ == "__main__":
    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    df = pd.read_csv(os.path.join(BASE, "data/raw/cyber_attacks/cybersecurity_attacks.csv"))
    df = score_dataframe(df)
    df.to_csv(os.path.join(BASE, "data/processed/alerts_scored.csv"), index=False)
    print(f"\n[✓] Sauvegardé dans data/processed/alerts_scored.csv")
    print("\n--- Exemples ---")
    print(df[['Attack Type', 'Severity Level', 'Malware Indicators',
              'Action Taken', 'Anomaly Scores', 'priority_score',
              'priority_level', 'reasons']].head(8).to_string())
