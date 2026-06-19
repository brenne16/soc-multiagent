import re
import json
import uuid
from datetime import datetime


class AgentExtracteur:
    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        
        # Les patterns pour détecter les différents types d'events
        self.patterns = {
            "authentication_failure": re.compile(
                r"(\w+ \d+ \d+:\d+:\d+).*Failed password for (\w+) from ([\d.]+) port (\d+)"
            ),
            "port_scan": re.compile(
                r"(\w+ \d+ \d+:\d+:\d+).*TCP SYN from ([\d.]+) port (\d+)"
            ),
            "http_suspicious_request": re.compile(
                r"(\w+ \d+ \d+:\d+:\d+).*apache2: ([\d.]+).*\"(GET|POST) ([^\s]+).*\" (\d+)"
            ),
            "privilege_escalation": re.compile(
                r"(\w+ \d+ \d+:\d+:\d+).*sudo:.*USER=(\w+).*COMMAND=(.*)"
            ),
            "lateral_movement": re.compile(
                r"(\w+ \d+ \d+:\d+:\d+).*smbd.*Connection from ([\d.]+) to share (\w+\$?)"
            ),
            "ddos_attempt": re.compile(
                r"(\w+ \d+ \d+:\d+:\d+).*UDP flood detected from ([\d.]+) packets=(\d+)/s"
            ),
        }

    def lire_logs(self) -> list[str]:
        """Lit le fichier de logs et retourne les lignes"""
        with open(self.log_file_path, "r") as f:
            return f.readlines()

    def parser_ligne(self, ligne: str) -> dict | None:
        """Parse une ligne de log et retourne un event structuré"""
        ligne = ligne.strip()
        if not ligne:
            return None

        for event_type, pattern in self.patterns.items():
            match = pattern.search(ligne)
            if match:
                return self._construire_event(event_type, match, ligne)

        return None

    def _construire_event(self, event_type: str, match, raw_log: str) -> dict:
        """Construit un event JSON structuré selon le type"""
        event = {
            "event_id": f"EVT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.now().isoformat() + "Z",
            "event_type": event_type,
            "raw_log": raw_log,
            "source": {},
            "destination": {},
            "protocol": "",
            "metadata": {}
        }

        if event_type == "authentication_failure":
            event["source"]["ip"] = match.group(3)
            event["source"]["port"] = int(match.group(4))
            event["destination"]["ip"] = "10.0.0.1"
            event["destination"]["port"] = 22
            event["protocol"] = "SSH"
            event["metadata"]["target_user"] = match.group(2)

        elif event_type == "port_scan":
            event["source"]["ip"] = match.group(2)
            event["destination"]["port"] = int(match.group(3))
            event["protocol"] = "TCP"

        elif event_type == "http_suspicious_request":
            event["source"]["ip"] = match.group(2)
            event["destination"]["ip"] = "10.0.0.5"
            event["destination"]["port"] = 80
            event["protocol"] = "HTTP"
            event["metadata"]["method"] = match.group(3)
            event["metadata"]["url"] = match.group(4)
            event["metadata"]["status_code"] = int(match.group(5))

        elif event_type == "privilege_escalation":
            event["source"]["ip"] = "10.0.0.12"
            event["protocol"] = "INTERNAL"
            event["metadata"]["target_user"] = match.group(2)
            event["metadata"]["command"] = match.group(3).strip()

        elif event_type == "lateral_movement":
            event["source"]["ip"] = match.group(2)
            event["destination"]["ip"] = "10.0.0.20"
            event["protocol"] = "SMB"
            event["metadata"]["share"] = match.group(3)

        elif event_type == "ddos_attempt":
            event["source"]["ip"] = match.group(2)
            event["destination"]["ip"] = "10.0.0.1"
            event["protocol"] = "UDP"
            event["metadata"]["packets_per_second"] = int(match.group(3))

        return event

    def grouper_events(self, events: list[dict]) -> list[dict]:
        """Regroupe les events similaires (ex: brute force = plusieurs auth failures)"""
        groupes = {}

        for event in events:
            cle = f"{event['event_type']}_{event['source'].get('ip', '')}"
            if cle not in groupes:
                groupes[cle] = event
                groupes[cle]["count"] = 1
            else:
                groupes[cle]["count"] += 1

        return list(groupes.values())

    def extraire(self) -> list[dict]:
        """Méthode principale — lit, parse et retourne les events structurés"""
        print("[Extracteur] Lecture des logs...")
        lignes = self.lire_logs()

        print(f"[Extracteur] {len(lignes)} lignes trouvées, parsing en cours...")
        events = []
        for ligne in lignes:
            event = self.parser_ligne(ligne)
            if event:
                events.append(event)

        print(f"[Extracteur] {len(events)} events détectés, regroupement...")
        events_groupes = self.grouper_events(events)

        print(f"[Extracteur] ✅ {len(events_groupes)} events uniques extraits")
        return events_groupes


# Test rapide
if __name__ == "__main__":
    extracteur = AgentExtracteur("data/logs/sample_logs.txt")
    events = extracteur.extraire()
    print(json.dumps(events, indent=2))