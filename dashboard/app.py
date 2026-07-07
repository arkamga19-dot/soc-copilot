import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import json
import sys, os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.scoring import compute_priority_score, score_dataframe
from src.mitre_matcher import load_playbooks, match_playbook

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYBOOKS_PATH = os.path.join(BASE, "data/raw/playbooks/incident_response_playbook_dataset.jsonl")

st.set_page_config(page_title="SOC Copilot", page_icon="🛡️", layout="wide")

@st.cache_resource
def get_playbooks():
    return load_playbooks(PLAYBOOKS_PATH)
playbooks = get_playbooks()

st.markdown('''<style>
@import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;700;800&family=JetBrains+Mono:wght@400;600&display=swap");
html,body,.stApp{background:#0a0e1a !important;}
section[data-testid="stSidebar"]{background:#0d1117 !important;border-right:1px solid #1e293b !important;}
.stButton>button{background:linear-gradient(135deg,#00ffa3,#60a5fa) !important;color:#000 !important;font-weight:700 !important;border:none !important;border-radius:10px !important;padding:12px 32px !important;font-size:15px !important;}
</style>''', unsafe_allow_html=True)

with st.sidebar:
    st.markdown('''<div style="text-align:center;padding:20px 0 8px">
        <div style="font-size:52px">🛡️</div>
        <div style="font-size:20px;font-weight:800;color:#00ffa3;font-family:Inter,sans-serif">SOC Copilot</div>
        <div style="font-size:12px;color:#64748b;margin-bottom:16px">Assistant IA — Corrélation SIEM</div>
    </div>''', unsafe_allow_html=True)
    st.markdown("---")
    mode = st.radio("Mode", ["🔍 Analyse manuelle", "📂 Analyse CSV"])
    st.markdown("---")
    st.markdown('<div style="font-size:11px;color:#334155;text-align:center">ECE Paris B3 — 2026<br>Armand · Khadija · Patricia</div>', unsafe_allow_html=True)

components.html('''
<canvas id="mx" style="position:absolute;top:0;left:0;width:100%;height:120px"></canvas>
<div style="position:relative;z-index:1;padding:20px 40px 10px">
  <div style="font-family:Inter,sans-serif;font-size:40px;font-weight:800;background:linear-gradient(135deg,#00ffa3,#60a5fa);-webkit-background-clip:text;-webkit-text-fill-color:transparent">🛡️ SOC Copilot</div>
  <div style="font-family:Inter,sans-serif;font-size:14px;color:#64748b;margin-top:4px">Corrélation et priorisation d\'alertes SIEM — Matching MITRE ATT&CK en temps réel</div>
</div>
<script>
const c=document.getElementById("mx"),ctx=c.getContext("2d");
c.width=800;c.height=120;
const ch="01アイウエオカキクケコ",fs=11,cols=Math.floor(c.width/fs),drops=Array(cols).fill(1);
setInterval(()=>{ctx.fillStyle="rgba(10,14,26,0.05)";ctx.fillRect(0,0,c.width,c.height);ctx.fillStyle="#00ffa322";ctx.font=fs+"px monospace";drops.forEach((y,i)=>{ctx.fillText(ch[Math.floor(Math.random()*ch.length)],i*fs,y*fs);if(y*fs>c.height&&Math.random()>.975)drops[i]=0;drops[i]++;});},50);
</script>
''', height=130)

if mode == "🔍 Analyse manuelle":
    col1, col2 = st.columns(2, gap="large")
    with col1:
        attack_type = st.selectbox("Type d\'attaque", ["DDoS", "Malware", "Intrusion"])
        severity    = st.selectbox("Niveau de sévérité", ["Critical", "High", "Medium", "Low"])
        malware_ind = st.selectbox("Indicateur malware", ["IoC Detected", "None"])
        action      = st.selectbox("Action prise", ["Ignored", "Logged", "Blocked"])
    with col2:
        anomaly  = st.slider("Anomaly Score", 0.0, 100.0, 50.0)
        src_port = st.number_input("Port source", min_value=1, max_value=65535, value=443)
        dst_port = st.number_input("Port destination", min_value=1, max_value=65535, value=80)

    if st.button("🔍 Analyser l\'alerte", type="primary"):
        row = {
            'Attack Type': attack_type, 'Severity Level': severity,
            'Malware Indicators': malware_ind if malware_ind != "None" else None,
            'Action Taken': action, 'Anomaly Scores': anomaly,
            'Source Port': src_port, 'Destination Port': dst_port
        }
        result = compute_priority_score(pd.Series(row))
        match  = match_playbook(attack_type, severity, playbooks)
        level  = result['priority_level']
        score  = int(result['priority_score'])
        dur    = match.get('response_duration_total_min', 'N/A')
        COLORS = {'CRITIQUE':'#ff3b3b','HAUTE':'#ff8c00','MOYENNE':'#f59e0b','FAIBLE':'#10b981'}
        color  = COLORS.get(level, '#888')
        bar_pct = round(min(score/175*100, 100), 1)
        reasons_json = json.dumps([r.strip() for r in result['reasons'].split('|')])
        steps_json   = json.dumps(match.get('playbook_steps', []))
        tactics_json = json.dumps(match.get('tactics_techniques', []))
        tags_json    = json.dumps(match.get('tags', []))
        incident     = match.get('incident_type', 'N/A')
        sev_match    = match.get('severity', 'N/A')

        html = f'''
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700;800&family=JetBrains+Mono:wght@600&display=swap" rel="stylesheet">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0e1a;color:#f1f5f9;font-family:Inter,sans-serif;padding:20px}}
@keyframes fadeUp{{from{{opacity:0;transform:translateY(20px)}}to{{opacity:1;transform:translateY(0)}}}}
@keyframes glow{{0%,100%{{box-shadow:0 0 10px 3px {color}66}}50%{{box-shadow:0 0 28px 10px {color}33}}}}
@keyframes barIn{{from{{width:0}}to{{width:{bar_pct}%}}}}
.cards{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}}
.card{{background:#111827;border:1px solid #1e293b;border-radius:16px;padding:24px;text-align:center;position:relative;overflow:hidden;animation:fadeUp .6s ease forwards;opacity:0}}
.card:nth-child(1){{animation-delay:0s}}.card:nth-child(2){{animation-delay:.15s}}.card:nth-child(3){{animation-delay:.3s}}
.card::before{{content:"";position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#00ffa3,#60a5fa)}}
.clabel{{font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px}}
.cval{{font-size:40px;font-weight:800;font-family:"JetBrains Mono",monospace;color:{color}}}
.badge{{display:inline-block;padding:10px 28px;border-radius:30px;font-weight:800;font-size:22px;letter-spacing:2px;background:{color}22;color:{color};border:2px solid {color};animation:glow 2s infinite}}
.pbar{{background:#1e293b;border-radius:8px;height:10px;margin:12px 0;overflow:hidden}}
.pfill{{height:100%;border-radius:8px;background:linear-gradient(90deg,{color},{color}88);animation:barIn 1.2s cubic-bezier(.4,0,.2,1) .3s both}}
.reasons{{background:#111827;border-left:3px solid #00ffa3;border-radius:0 10px 10px 0;padding:14px 18px;margin:16px 0;animation:fadeUp .6s ease .4s forwards;opacity:0}}
.rtag{{display:inline-block;background:#00ffa308;border:1px solid #00ffa344;border-radius:6px;padding:3px 10px;margin:3px;font-family:"JetBrains Mono",monospace;font-size:12px;color:#00ffa3}}
.sec{{font-size:13px;font-weight:700;color:#60a5fa;text-transform:uppercase;letter-spacing:2px;margin:24px 0 14px;display:flex;align-items:center;gap:8px}}
.sec::after{{content:"";flex:1;height:1px;background:linear-gradient(90deg,#60a5fa22,transparent)}}
.pbcard{{background:#111827;border:1px solid #1e293b;border-radius:14px;padding:20px;animation:fadeUp .6s ease .5s forwards;opacity:0}}
.pbtitle{{font-size:20px;font-weight:700;margin-bottom:4px}}
.pbmeta{{font-size:13px;color:#64748b;margin-bottom:14px}}
.mtag{{display:inline-block;background:#60a5fa12;color:#60a5fa;border:1px solid #60a5fa44;border-radius:6px;padding:3px 10px;font-size:12px;font-weight:600;margin:3px}}
.tl{{position:relative;padding-left:32px;margin-top:8px}}
.tl::before{{content:"";position:absolute;left:10px;top:0;bottom:0;width:2px;background:linear-gradient(#00ffa3,#60a5fa);border-radius:2px}}
.ts{{position:relative;margin-bottom:18px;animation:fadeUp .5s ease forwards;opacity:0}}
.ts:nth-child(1){{animation-delay:.6s}}.ts:nth-child(2){{animation-delay:.75s}}.ts:nth-child(3){{animation-delay:.9s}}.ts:nth-child(4){{animation-delay:1.05s}}.ts:nth-child(5){{animation-delay:1.2s}}
.ts::before{{content:"";position:absolute;left:-26px;top:4px;width:12px;height:12px;border-radius:50%;background:#00ffa3;box-shadow:0 0 10px #00ffa3;border:2px solid #0a0e1a}}
.tsph{{font-size:11px;font-weight:700;color:#00ffa3;text-transform:uppercase;letter-spacing:1.5px}}
.tsac{{font-size:14px;color:#f1f5f9;margin:4px 0}}
.tstl{{font-size:12px;color:#475569}}
</style>
<div class="cards">
  <div class="card"><div class="clabel">Priorité</div><div style="margin-top:8px"><span class="badge">{level}</span></div></div>
  <div class="card"><div class="clabel">Score de risque</div><div class="cval">{score}</div><div class="pbar"><div class="pfill"></div></div><div style="font-size:11px;color:#475569">sur 175</div></div>
  <div class="card"><div class="clabel">Durée de réponse</div><div class="cval">{dur}<span style="font-size:16px;color:#64748b"> min</span></div></div>
</div>
<div class="reasons" id="rea"></div>
<div class="sec">Playbook recommandé</div>
<div class="pbcard">
  <div class="pbtitle">{incident}</div>
  <div class="pbmeta">Sévérité : {sev_match} · Durée : {dur} min · <span id="tgs"></span></div>
  <div id="tac"></div>
</div>
<div class="sec">Étapes de réponse</div>
<div class="tl" id="tl"></div>
<script>
document.getElementById("rea").innerHTML="⚡ "+{reasons_json}.map(r=>`<span class="rtag">${{r}}</span>`).join(" ");
document.getElementById("tgs").innerHTML={tags_json}.map(t=>`<span class="mtag">${{t}}</span>`).join("");
document.getElementById("tac").innerHTML={tactics_json}.map(t=>`<span class="mtag">${{t.tactic}} → ${{t.technique}}</span>`).join("");
document.getElementById("tl").innerHTML={steps_json}.map(s=>`<div class="ts"><div class="tsph">${{s.phase}} — ${{s.response_time_min}} min</div><div class="tsac">${{s.action}}</div><div class="tstl">🛠 ${{(s.tools||[]).join(", ")}}</div></div>`).join("");
</script>
'''
        components.html(html, height=1000, scrolling=True)

else:
    import plotly.express as px
    uploaded = st.file_uploader("Glisse ton fichier CSV ici", type="csv")
    if uploaded:
        df = pd.read_csv(uploaded)
        df = score_dataframe(df)
        COLORS = {'CRITIQUE':'#ff3b3b','HAUTE':'#ff8c00','MOYENNE':'#f59e0b','FAIBLE':'#10b981'}
        counts = {l: len(df[df['priority_level']==l]) for l in ['CRITIQUE','HAUTE','MOYENNE','FAIBLE']}

        c_val = counts['CRITIQUE']
        h_val = counts['HAUTE']
        m_val = counts['MOYENNE']
        f_val = counts['FAIBLE']

        html_csv = f'''
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@700;800&family=JetBrains+Mono:wght@600&display=swap" rel="stylesheet">
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{background:#0a0e1a;font-family:Inter,sans-serif;padding:20px}}@keyframes fadeUp{{from{{opacity:0;transform:translateY(20px)}}to{{opacity:1;transform:translateY(0)}}}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}}.mc{{background:#111827;border:1px solid #1e293b;border-radius:14px;padding:20px;text-align:center;position:relative;overflow:hidden;animation:fadeUp .5s ease forwards;opacity:0}}.mc:nth-child(1){{animation-delay:0s;border-top:3px solid #ff3b3b}}.mc:nth-child(2){{animation-delay:.1s;border-top:3px solid #ff8c00}}.mc:nth-child(3){{animation-delay:.2s;border-top:3px solid #f59e0b}}.mc:nth-child(4){{animation-delay:.3s;border-top:3px solid #10b981}}.ml{{font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:2px;margin-bottom:10px}}.mv{{font-size:38px;font-weight:800;font-family:"JetBrains Mono",monospace}}</style>
<div class="grid">
  <div class="mc"><div class="ml">🔴 Critique</div><div class="mv" style="color:#ff3b3b">{c_val}</div></div>
  <div class="mc"><div class="ml">🟠 Haute</div><div class="mv" style="color:#ff8c00">{h_val}</div></div>
  <div class="mc"><div class="ml">🟡 Moyenne</div><div class="mv" style="color:#f59e0b">{m_val}</div></div>
  <div class="mc"><div class="ml">🟢 Faible</div><div class="mv" style="color:#10b981">{f_val}</div></div>
</div>
'''
        components.html(html_csv, height=160)

        cl, cr = st.columns(2, gap="large")
        with cl:
            fig = px.pie(df, names='priority_level', title='Distribution des priorités', color='priority_level', color_discrete_map=COLORS, hole=0.5)
            fig.update_layout(paper_bgcolor='rgba(0,0,0,0)', font_color='#94a3b8', title_font_color='#f1f5f9')
            st.plotly_chart(fig, use_container_width=True)
        with cr:
            fig2 = px.histogram(df, x='Attack Type', color='priority_level', title="Alertes par type d\'attaque", color_discrete_map=COLORS, barmode='group')
            fig2.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='#94a3b8', title_font_color='#f1f5f9')
            st.plotly_chart(fig2, use_container_width=True)

        urgent = df[df['priority_level'].isin(['CRITIQUE','HAUTE'])][
            ['Attack Type','Severity Level','Malware Indicators','Action Taken','priority_score','priority_level','reasons']
        ].sort_values('priority_score', ascending=False)
        st.dataframe(urgent, use_container_width=True, height=400)
