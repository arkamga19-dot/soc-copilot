import streamlit as st
import pandas as pd
import plotly.express as px
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.scoring import compute_priority_score
from src.mitre_matcher import load_playbooks, match_playbook, format_recommendation

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYBOOKS_PATH = os.path.join(BASE, "data/raw/playbooks/incident_response_playbook_dataset.jsonl")

st.set_page_config(
    page_title="SOC Copilot",
    page_icon="🛡️",
    layout="wide"
)

@st.cache_resource
def get_playbooks():
    return load_playbooks(PLAYBOOKS_PATH)

playbooks = get_playbooks()

# ── Sidebar ──────────────────────────────────────────────
st.sidebar.image("https://img.icons8.com/color/96/security-shield-green.png", width=80)
st.sidebar.title("SOC Copilot")
st.sidebar.markdown("Assistant IA de corrélation et priorisation d'alertes SIEM")
st.sidebar.markdown("---")
mode = st.sidebar.radio("Mode", ["Analyse manuelle", "Analyse par fichier CSV"])

# ── Header ───────────────────────────────────────────────
st.title("🛡️ SOC Copilot — Corrélation d'alertes SIEM")
st.markdown("Priorisez vos alertes et obtenez un playbook de réponse en temps réel.")
st.markdown("---")

# ── Mode 1 : Analyse manuelle ────────────────────────────
if mode == "Analyse manuelle":
    st.subheader("Analyse d'une alerte")

    col1, col2 = st.columns(2)
    with col1:
        attack_type = st.selectbox("Type d'attaque", ["DDoS", "Malware", "Intrusion"])
        severity = st.selectbox("Niveau de sévérité", ["Critical", "High", "Medium", "Low"])
        malware_ind = st.selectbox("Indicateur malware", ["IoC Detected", "None"])
        action = st.selectbox("Action prise", ["Ignored", "Logged", "Blocked"])
    with col2:
        anomaly = st.slider("Anomaly Score", 0.0, 100.0, 50.0)
        src_port = st.number_input("Port source", min_value=1, max_value=65535, value=443)
        dst_port = st.number_input("Port destination", min_value=1, max_value=65535, value=80)

    if st.button("🔍 Analyser l'alerte", type="primary"):
        row = {
            'Attack Type': attack_type,
            'Severity Level': severity,
            'Malware Indicators': malware_ind if malware_ind != "None" else None,
            'Action Taken': action,
            'Anomaly Scores': anomaly,
            'Source Port': src_port,
            'Destination Port': dst_port
        }

        result = compute_priority_score(pd.Series(row))
        match = match_playbook(attack_type, severity, playbooks)

        st.markdown("---")
        col_a, col_b, col_c = st.columns(3)

        color_map = {'CRITIQUE': '🔴', 'HAUTE': '🟠', 'MOYENNE': '🟡', 'FAIBLE': '🟢'}
        emoji = color_map.get(result['priority_level'], '⚪')

        col_a.metric("Priorité", f"{emoji} {result['priority_level']}")
        col_b.metric("Score", result['priority_score'])
        col_c.metric("Durée de réponse", f"{match.get('response_duration_total_min', 'N/A')} min")

        st.markdown("**Raisons du scoring :**")
        st.info(result['reasons'])

        st.markdown("---")
        st.subheader("📋 Playbook recommandé")
        st.markdown(f"**{match.get('incident_type', 'N/A')}** — Sévérité : {match.get('severity', 'N/A')}")

        if match.get('tactics_techniques'):
            st.markdown("**Tactiques MITRE ATT&CK :**")
            for tt in match['tactics_techniques']:
                st.markdown(f"- `{tt['tactic']}` → {tt['technique']}")

        if match.get('playbook_steps'):
            st.markdown("**Étapes de réponse :**")
            for step in match['playbook_steps']:
                with st.expander(f"{step['phase']} — {step['response_time_min']} min"):
                    st.write(f"**Action :** {step['action']}")
                    st.write(f"**Outils :** {', '.join(step.get('tools', []))}")

# ── Mode 2 : Analyse CSV ─────────────────────────────────
else:
    st.subheader("Analyse d'un fichier d'alertes")
    uploaded = st.file_uploader("Importe ton fichier CSV d'alertes", type="csv")

    if uploaded:
        df = pd.read_csv(uploaded)
        st.success(f"{len(df)} alertes chargées")

        from src.scoring import score_dataframe
        df = score_dataframe(df)

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🔴 Critique", len(df[df['priority_level'] == 'CRITIQUE']))
        col2.metric("🟠 Haute", len(df[df['priority_level'] == 'HAUTE']))
        col3.metric("🟡 Moyenne", len(df[df['priority_level'] == 'MOYENNE']))
        col4.metric("🟢 Faible", len(df[df['priority_level'] == 'FAIBLE']))

        fig = px.pie(df, names='priority_level', title='Distribution des priorités',
                     color='priority_level',
                     color_discrete_map={
                         'CRITIQUE': '#e74c3c',
                         'HAUTE': '#e67e22',
                         'MOYENNE': '#f1c40f',
                         'FAIBLE': '#2ecc71'
                     })
        st.plotly_chart(fig, use_container_width=True)

        fig2 = px.histogram(df, x='Attack Type', color='priority_level',
                            title='Alertes par type d\'attaque et priorité',
                            color_discrete_map={
                                'CRITIQUE': '#e74c3c',
                                'HAUTE': '#e67e22',
                                'MOYENNE': '#f1c40f',
                                'FAIBLE': '#2ecc71'
                            })
        st.plotly_chart(fig2, use_container_width=True)

        st.markdown("### Alertes CRITIQUES et HAUTES")
        urgent = df[df['priority_level'].isin(['CRITIQUE', 'HAUTE'])][
            ['Attack Type', 'Severity Level', 'Malware Indicators',
             'Action Taken', 'priority_score', 'priority_level', 'reasons']
        ].sort_values('priority_score', ascending=False)
        st.dataframe(urgent, use_container_width=True)
