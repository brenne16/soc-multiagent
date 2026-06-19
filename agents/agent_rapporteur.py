"""
Agent Rapporteur — SOC Multi-Agents
Lit les événements analysés (sortie de l'Agent Analyseur) et génère :
  1. Un rapport d'incident détaillé (texte, via Mistral)
  2. Un dashboard synthétique (JSON)
"""

import json
from datetime import datetime
from collections import defaultdict
from langchain_ollama import OllamaLLM
from langchain_core.prompts import ChatPromptTemplate

# ----------------------------------------------------------------------
# 1. Chargement des données analysées
# ----------------------------------------------------------------------

def load_analyzed_events(filepath: str) -> list:
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


# ----------------------------------------------------------------------
# 2. Regroupement des événements corrélés en "incidents"
#    (deux events qui se référencent mutuellement = un seul incident)
# ----------------------------------------------------------------------

def group_into_incidents(events: list) -> list:
    events_by_id = {e["event_id"]: e for e in events}
    visited = set()
    incidents = []

    for event in events:
        eid = event["event_id"]
        if eid in visited:
            continue

        # BFS simple pour récupérer tous les events corrélés
        cluster = [eid]
        visited.add(eid)
        queue = list(event["analysis"].get("correlated_events", []))

        while queue:
            cid = queue.pop()
            if cid in visited or cid not in events_by_id:
                continue
            visited.add(cid)
            cluster.append(cid)
            queue.extend(events_by_id[cid]["analysis"].get("correlated_events", []))

        incident_events = [events_by_id[i] for i in cluster]
        incidents.append(build_incident(incident_events))

    return incidents


def build_incident(events: list) -> dict:
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_severity = max(events, key=lambda e: severity_rank.get(e["analysis"]["severity"], 0))

    return {
        "incident_id": "INC-" + events[0]["event_id"].split("-")[1],
        "events": events,
        "source_ips": sorted(set(e["source_ip"] for e in events)),
        "attack_types": sorted(set(e["analysis"]["attack_type"] for e in events)),
        "severity": max_severity["analysis"]["severity"],
        "recommended_actions": sorted(set(e["analysis"]["recommended_action"] for e in events)),
        "avg_confidence": round(sum(e["analysis"]["confidence"] for e in events) / len(events), 2),
        "timestamp": min(e["timestamp"] for e in events),
    }


# ----------------------------------------------------------------------
# 3. Génération du rapport texte via Mistral
# ----------------------------------------------------------------------

REPORT_PROMPT = ChatPromptTemplate.from_messages([
    ("system",
     "Tu es un analyste SOC senior. Tu rédiges des rapports d'incidents clairs, "
     "professionnels et actionnables pour une équipe de sécurité. "
     "Structure ta réponse en 4 parties : Résumé, Détails techniques, "
     "Impact potentiel, Recommandations. Reste concis (200 mots max)."),
    ("human",
     "Voici un incident de sécurité à documenter :\n\n"
     "ID incident: {incident_id}\n"
     "IP(s) source: {source_ips}\n"
     "Type(s) d'attaque: {attack_types}\n"
     "Sévérité: {severity}\n"
     "Confiance moyenne: {avg_confidence}\n"
     "Actions recommandées: {recommended_actions}\n"
     "Détails des événements: {events_summary}\n\n"
     "Rédige le rapport d'incident.")
])


def generate_text_report(incident: dict, llm) -> str:
    events_summary = "\n".join(
        f"- {e['event_type']} ({e['analysis']['attack_type']}): "
        f"{', '.join(e['analysis']['indicators'])}"
        for e in incident["events"]
    )

    chain = REPORT_PROMPT | llm
    return chain.invoke({
        "incident_id": incident["incident_id"],
        "source_ips": ", ".join(incident["source_ips"]),
        "attack_types": ", ".join(incident["attack_types"]),
        "severity": incident["severity"],
        "avg_confidence": incident["avg_confidence"],
        "recommended_actions": ", ".join(incident["recommended_actions"]),
        "events_summary": events_summary,
    })


# ----------------------------------------------------------------------
# 4. Dashboard synthétique (JSON, pour visualisation/bonus)
# ----------------------------------------------------------------------

def build_dashboard(incidents: list) -> dict:
    severity_count = defaultdict(int)
    action_count = defaultdict(int)
    attack_type_count = defaultdict(int)

    for inc in incidents:
        severity_count[inc["severity"]] += 1
        for action in inc["recommended_actions"]:
            action_count[action] += 1
        for atype in inc["attack_types"]:
            attack_type_count[atype] += 1

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_incidents": len(incidents),
        "by_severity": dict(severity_count),
        "by_recommended_action": dict(action_count),
        "by_attack_type": dict(attack_type_count),
        "incidents_overview": [
            {
                "incident_id": inc["incident_id"],
                "severity": inc["severity"],
                "attack_types": inc["attack_types"],
                "source_ips": inc["source_ips"],
            }
            for inc in incidents
        ],
    }


# ----------------------------------------------------------------------
# 5. Pipeline principal
# ----------------------------------------------------------------------

def run_agent_rapporteur(input_path: str, output_dir: str = "."):
    print("📥 Chargement des événements analysés...")
    events = load_analyzed_events(input_path)
    print(f"   → {len(events)} événements chargés")

    print("🔗 Regroupement en incidents corrélés...")
    incidents = group_into_incidents(events)
    print(f"   → {len(incidents)} incident(s) identifié(s)")

    print("🤖 Connexion à Mistral...")
    llm = OllamaLLM(model="mistral")

    full_report_text = []
    for incident in incidents:
        print(f"   ✏️  Génération du rapport pour {incident['incident_id']}...")
        text = generate_text_report(incident, llm)
        full_report_text.append(f"## Incident {incident['incident_id']}\n\n{text}\n")

    # Sauvegarde du rapport texte (Markdown)
    report_path = f"{output_dir}/rapport_incidents.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# Rapport SOC — {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC\n\n")
        f.write("\n---\n\n".join(full_report_text))
    print(f"✅ Rapport texte sauvegardé : {report_path}")

    # Sauvegarde du dashboard JSON
    dashboard = build_dashboard(incidents)
    dashboard_path = f"{output_dir}/dashboard.json"
    with open(dashboard_path, "w", encoding="utf-8") as f:
        json.dump(dashboard, f, indent=2, ensure_ascii=False)
    print(f"✅ Dashboard sauvegardé : {dashboard_path}")

    return incidents, dashboard


if __name__ == "__main__":
    run_agent_rapporteur("analyzed_events.json", output_dir=".")