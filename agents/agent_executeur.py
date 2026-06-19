"""
Agent Exécuteur — SOC Multi-Agents
Lit les incidents (sortie de l'Agent Rapporteur / Analyseur) et :
  1. Simule les actions de remédiation (block_ip, isolate_machine)
  2. Envoie une notification email à l'admin pour les incidents critiques/high
  3. Trace toutes les actions dans un log d'audit horodaté
"""

import json
import os
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()  # charge les variables depuis le fichier .env

AUDIT_LOG_PATH = "audit_log.jsonl"  # un événement JSON par ligne, facile à parser/append

# ----------------------------------------------------------------------
# 1. Chargement des incidents (depuis le dashboard ou directement les events)
# ----------------------------------------------------------------------

def load_incidents(filepath: str) -> list:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Supporte soit un dashboard.json (incidents_overview), soit une liste brute d'incidents
    if isinstance(data, dict) and "incidents_overview" in data:
        return data["incidents_overview"]
    return data


# ----------------------------------------------------------------------
# 2. Simulation des actions de remédiation
# ----------------------------------------------------------------------

def simulate_action(incident: dict) -> dict:
    """
    Simule l'exécution d'une action de remédiation.
    Ne touche à AUCUN système réel — uniquement une décision + log.
    """
    severity = incident.get("severity", "unknown")
    source_ips = incident.get("source_ips", [])
    attack_types = incident.get("attack_types", [])

    # Détermine l'action à partir de la sévérité (logique simple et explicable)
    if severity == "critical":
        action = "isolate_machine"
    elif severity in ("high", "medium"):
        action = "block_ip"
    else:
        action = "monitor_only"

    result = {
        "incident_id": incident.get("incident_id"),
        "action_taken": action,
        "target_ips": source_ips,
        "attack_types": attack_types,
        "severity": severity,
        "status": "SIMULATED_SUCCESS",
        "executed_at": datetime.utcnow().isoformat() + "Z",
    }

    print(f"   🛡️  [{severity.upper()}] Incident {result['incident_id']} "
          f"→ ACTION SIMULÉE: {action} sur {source_ips}")

    return result


# ----------------------------------------------------------------------
# 3. Traçabilité — log d'audit (append-only, format JSONL)
# ----------------------------------------------------------------------

def write_audit_log(action_result: dict, log_path: str = AUDIT_LOG_PATH):
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(action_result, ensure_ascii=False) + "\n")


# ----------------------------------------------------------------------
# 4. Notification email pour les incidents critiques/high
# ----------------------------------------------------------------------

def send_email_notification(action_results: list):
    gmail_address = os.getenv("GMAIL_ADDRESS")
    gmail_password = os.getenv("GMAIL_APP_PASSWORD")
    admin_email = os.getenv("ADMIN_EMAIL")

    if not all([gmail_address, gmail_password, admin_email]):
        print("⚠️  Variables .env manquantes — notification email ignorée.")
        return False

    # On ne notifie que pour les actions importantes (pas le monitor_only)
    important = [r for r in action_results if r["action_taken"] != "monitor_only"]
    if not important:
        print("ℹ️  Aucun incident critique/high — pas de notification envoyée.")
        return False

    body_lines = ["Rapport d'actions automatiques — Agent Exécuteur SOC\n"]
    for r in important:
        body_lines.append(
            f"- Incident {r['incident_id']} | Sévérité: {r['severity']} | "
            f"Action: {r['action_taken']} | IP(s): {', '.join(r['target_ips'])} | "
            f"Statut: {r['status']}"
        )
    body = "\n".join(body_lines)

    msg = MIMEMultipart()
    msg["From"] = gmail_address
    msg["To"] = admin_email
    msg["Subject"] = f"[SOC ALERT] {len(important)} incident(s) traité(s) — {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC"
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(gmail_address, gmail_password)
            server.sendmail(gmail_address, admin_email, msg.as_string())
        print(f"✅ Email de notification envoyé à {admin_email}")
        return True
    except Exception as e:
        print(f"❌ Échec d'envoi de l'email : {e}")
        return False


# ----------------------------------------------------------------------
# 5. Pipeline principal
# ----------------------------------------------------------------------

def run_agent_executeur(input_path: str = "dashboard.json"):
    print("📥 Chargement des incidents...")
    incidents = load_incidents(input_path)
    print(f"   → {len(incidents)} incident(s) à traiter")

    print("🛡️  Exécution des actions de remédiation (simulation)...")
    action_results = []
    for incident in incidents:
        result = simulate_action(incident)
        write_audit_log(result)
        action_results.append(result)

    print(f"📝 Log d'audit mis à jour : {AUDIT_LOG_PATH}")

    print("📧 Envoi des notifications admin...")
    send_email_notification(action_results)

    print("\n✅ Agent Exécuteur terminé.")
    return action_results


if __name__ == "__main__":
    run_agent_executeur("dashboard.json")