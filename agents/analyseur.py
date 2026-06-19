import json
from agents.llm_helper import LLMHelper


class AgentAnalyseur:
    def __init__(self, use_llm: bool = True):
        # Seuils pour le moteur de règles
        self.seuils = {
            "brute_force_count": 3,       # +3 tentatives = brute force probable
            "port_scan_count": 3,          # +3 ports différents = scan probable
            "ddos_pps": 1000,              # +1000 paquets/sec = DDoS probable
        }

        self.use_llm = use_llm
        if use_llm:
            self.llm_helper = LLMHelper()

    def appliquer_regles(self, event: dict) -> dict:
        """Moteur de règles — détection rapide des cas évidents"""
        event_type = event["event_type"]
        count = event.get("count", 1)

        analysis = {
            "attack_type": None,
            "confidence": 0.0,
            "severity": "low",
            "correlated_events": [],
            "indicators": [],
            "recommended_action": "monitor",
            "explanation": ""
        }

        if event_type == "authentication_failure" and count >= self.seuils["brute_force_count"]:
            analysis["attack_type"] = "brute_force_ssh"
            analysis["confidence"] = min(0.7 + (count * 0.02), 0.99)
            analysis["severity"] = "critical" if count > 50 else "high"
            analysis["indicators"].append(f"{count} tentatives de connexion échouées")
            if event["metadata"].get("target_user") == "root":
                analysis["indicators"].append("Ciblage du compte root")
            analysis["recommended_action"] = "block_ip"

        elif event_type == "port_scan" and count >= self.seuils["port_scan_count"]:
            analysis["attack_type"] = "port_scan"
            analysis["confidence"] = min(0.6 + (count * 0.05), 0.95)
            analysis["severity"] = "high" if count > 10 else "medium"
            analysis["indicators"].append(f"{count} ports scannés en peu de temps")
            analysis["recommended_action"] = "block_ip"

        elif event_type == "http_suspicious_request":
            analysis["attack_type"] = "sql_injection"
            analysis["confidence"] = 0.85
            analysis["severity"] = "high"
            analysis["indicators"].append("Payload suspect détecté dans la requête HTTP")
            analysis["indicators"].append(f"Status code {event['metadata'].get('status_code')} (erreur serveur)")
            analysis["recommended_action"] = "block_ip"

        elif event_type == "privilege_escalation":
            analysis["attack_type"] = "privilege_escalation"
            analysis["confidence"] = 0.8
            analysis["severity"] = "critical"
            analysis["indicators"].append(f"Élévation de privilèges vers {event['metadata'].get('target_user')}")
            analysis["indicators"].append(f"Commande exécutée: {event['metadata'].get('command')}")
            analysis["recommended_action"] = "isolate_machine"

        elif event_type == "lateral_movement":
            analysis["attack_type"] = "lateral_movement"
            analysis["confidence"] = 0.75
            analysis["severity"] = "critical"
            analysis["indicators"].append(f"Connexion SMB suspecte vers {event['metadata'].get('share')}")
            analysis["recommended_action"] = "isolate_machine"

        elif event_type == "ddos_attempt":
            pps = event["metadata"].get("packets_per_second", 0)
            if pps >= self.seuils["ddos_pps"]:
                analysis["attack_type"] = "ddos_udp_flood"
                analysis["confidence"] = 0.9
                analysis["severity"] = "high"
                analysis["indicators"].append(f"{pps} paquets/seconde détectés")
                analysis["recommended_action"] = "block_ip"

        else:
            analysis["attack_type"] = "unknown"
            analysis["severity"] = "low"
            analysis["recommended_action"] = "monitor"

        return analysis

    def correler_events(self, events: list[dict]) -> list[dict]:
        """Trouve les events liés entre eux (même IP source)"""
        for event in events:
            ip_source = event.get("source", {}).get("ip")
            if not ip_source:
                continue

            correles = [
                e["event_id"] for e in events
                if e["event_id"] != event["event_id"]
                and e.get("source", {}).get("ip") == ip_source
            ]
            event["_analysis"]["correlated_events"] = correles

        return events

    def analyser(self, events: list[dict]) -> list[dict]:
        """Méthode principale — analyse tous les events"""
        print("[Analyseur] Application du moteur de règles...")

        for event in events:
            event["_analysis"] = self.appliquer_regles(event)

        print("[Analyseur] Corrélation des events...")
        events = self.correler_events(events)

        if self.use_llm:
            print("[Analyseur] Génération des explications via Mistral...")
            for event in events:
                if event["_analysis"]["attack_type"] != "unknown":
                    explanation = self.llm_helper.generer_explication(event, event["_analysis"])
                    event["_analysis"]["explanation"] = explanation
                    print(f"  → {event['event_id']}: explication générée")

        print(f"[Analyseur] ✅ {len(events)} events analysés")

        # Reformater en JSON final (format B)
        resultats = []
        for event in events:
            resultats.append({
                "event_id": event["event_id"],
                "timestamp": event["timestamp"],
                "source_ip": event.get("source", {}).get("ip", "unknown"),
                "event_type": event["event_type"],
                "analysis": event["_analysis"]
            })

        return resultats


# Test rapide
if __name__ == "__main__":
    with open("data/output/extracted_events.json", "r") as f:
        events = json.load(f)

    analyseur = AgentAnalyseur()
    resultats = analyseur.analyser(events)

    print(json.dumps(resultats, indent=2, ensure_ascii=False))

    with open("data/output/analyzed_events.json", "w") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)