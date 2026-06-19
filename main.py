import json
from agents.extracteur import AgentExtracteur
from agents.analyseur import AgentAnalyseur
from agents.agent_rapporteur import run_agent_rapporteur
from agents.agent_executeur import run_agent_executeur


def main():
    print("=" * 60)
    print("PIPELINE SOC MULTI-AGENTS — démarrage")
    print("=" * 60)

    # ---------- Étape 1 — Agent Extracteur ----------
    print("\n--- [1/4] Agent Extracteur ---")
    extracteur = AgentExtracteur("data/logs/sample_logs.txt")
    events_extraits = extracteur.extraire()

    with open("data/output/extracted_events.json", "w", encoding="utf-8") as f:
        json.dump(events_extraits, f, indent=2, ensure_ascii=False)

    # ---------- Étape 2 — Agent Analyseur ----------
    print("\n--- [2/4] Agent Analyseur ---")
    analyseur = AgentAnalyseur()
    events_analyses = analyseur.analyser(events_extraits)

    with open("data/output/analyzed_events.json", "w", encoding="utf-8") as f:
        json.dump(events_analyses, f, indent=2, ensure_ascii=False)

    # ---------- Étape 3 — Agent Rapporteur ----------
    print("\n--- [3/4] Agent Rapporteur ---")
    incidents, dashboard = run_agent_rapporteur(
        "data/output/analyzed_events.json",
        output_dir="data/output"
    )

    # ---------- Étape 4 — Agent Exécuteur ----------
    print("\n--- [4/4] Agent Exécuteur ---")
    action_results = run_agent_executeur("data/output/dashboard.json")

    print("\n" + "=" * 60)
    print("✅ PIPELINE COMPLET TERMINÉ")
    print(f"   - {len(events_extraits)} événements extraits")
    print(f"   - {len(events_analyses)} événements analysés")
    print(f"   - {len(incidents)} incidents identifiés")
    print(f"   - {len(action_results)} actions exécutées (simulées)")
    print("=" * 60)


if __name__ == "__main__":
    main()