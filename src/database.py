import os
import pandas as pd
from dotenv import load_dotenv
from sqlalchemy import create_engine

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///soc_copilot.db")
engine = create_engine(DATABASE_URL)

def load_alerts(df: pd.DataFrame):
    df.to_sql("alerts", engine, if_exists="append", index=False)

def get_critical_alerts():
    return pd.read_sql(
        "SELECT * FROM alerts WHERE priority_level = 'CRITIQUE' "
        "ORDER BY priority_score DESC", engine)

def count_critical_by_attack():
    return pd.read_sql(
        "SELECT attack_type, COUNT(*) AS nb FROM alerts "
        "WHERE priority_level = 'CRITIQUE' GROUP BY attack_type", engine)

if __name__ == "__main__":
    demo = pd.DataFrame([
        {"attack_type": "Malware", "severity": "Critical", "priority_score": 165, "priority_level": "CRITIQUE"},
        {"attack_type": "Intrusion", "severity": "High", "priority_score": 130, "priority_level": "HAUTE"},
        {"attack_type": "DDoS", "severity": "Low", "priority_score": 40, "priority_level": "FAIBLE"},
    ])
    load_alerts(demo)
    print(get_critical_alerts())
    print(count_critical_by_attack())
