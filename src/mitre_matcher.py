import json
import os

def load_playbooks(path: str) -> list:
    playbooks = []
    with open(path, 'r', encoding='utf-8') as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                playbooks.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    print(f"[✓] {len(playbooks)} playbooks chargés")
    return playbooks

def match_playbook(attack_type: str, severity: str, playbooks: list) -> dict:
    attack_type = attack_type.lower().strip()
    severity = severity.lower().strip()

    # Mapping attack_type → mots-clés incident_type dans les playbooks
    type_keywords = {
        'ddos': ['ddos', 'denial', 'flood', 'volumetric'],
        'malware': ['malware', 'ransomware', 'trojan', 'virus', 'spyware'],
        'intrusion': ['intrusion', 'breach', 'unauthorized', 'lateral', 'privilege']
    }

    # Mapping severity → severity dans les playbooks
    severity_map = {
        'critique': 'critical',
        'haute': 'high',
        'moyenne': 'medium',
        'faible': 'low',
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low'
    }

    target_severity = severity_map.get(severity, 'medium')
    keywords = type_keywords.get(attack_type, [attack_type])

    best_match = None
    best_score = 0

    for pb in playbooks:
        score = 0
        pb_type = pb.get('incident_type', '').lower()
        pb_severity = pb.get('severity', '').lower()
        pb_tags = [t.lower() for t in pb.get('tags', [])]

        # Match sur le type d'incident
        for kw in keywords:
            if kw in pb_type:
                score += 10
            if any(kw in tag for tag in pb_tags):
                score += 5

        # Bonus si la sévérité correspond
        if pb_severity == target_severity:
            score += 8

        if score > best_score:
            best_score = score
            best_match = pb

    if best_match and best_score > 0:
        return {
            'match_score': best_score,
            'incident_type': best_match.get('incident_type'),
            'severity': best_match.get('severity'),
            'playbook_steps': best_match.get('playbook_steps', []),
            'tactics_techniques': best_match.get('tactics_techniques', []),
            'response_duration_total_min': best_match.get('response_duration_total_min'),
            'tags': best_match.get('tags', [])
        }
    return {
        'match_score': 0,
        'incident_type': 'Unknown',
        'severity': severity,
        'playbook_steps': [],
        'tactics_techniques': [],
        'response_duration_total_min': None,
        'tags': []
    }

def format_recommendation(match: dict) -> str:
    if match['match_score'] == 0:
        return "Aucun playbook trouvé pour cette alerte."

    lines = []
    lines.append(f"Incident type : {match['incident_type']}")
    lines.append(f"Sévérité : {match['severity']}")
    lines.append(f"Durée de réponse estimée : {match['response_duration_total_min']} min")
    lines.append(f"Tags : {', '.join(match['tags'])}")
    lines.append("\nTactiques MITRE ATT&CK :")
    for tt in match['tactics_techniques']:
        lines.append(f"  - [{tt['tactic']}] {tt['technique']}")
    lines.append("\nÉtapes de réponse :")
    for step in match['playbook_steps']:
        tools = ', '.join(step.get('tools', []))
        lines.append(f"  {step['phase']} ({step['response_time_min']} min) : {step['action']}")
        lines.append(f"    Outils : {tools}")
    return '\n'.join(lines)

if __name__ == "__main__":
    BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    playbooks_path = os.path.join(BASE, "data/raw/playbooks/incident_response_playbook_dataset.jsonl")
    playbooks = load_playbooks(playbooks_path)

    # Tests sur les 3 types d'attaques
    test_cases = [
        ('DDoS', 'High'),
        ('Malware', 'Critical'),
        ('Intrusion', 'Medium'),
    ]

    for attack, sev in test_cases:
        print(f"\n{'='*60}")
        print(f"ALERTE : {attack} | Sévérité : {sev}")
        print('='*60)
        match = match_playbook(attack, sev, playbooks)
        print(format_recommendation(match))
