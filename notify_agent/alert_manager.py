import os
import logging
from dotenv import load_dotenv
from agent_email import email_agent  # On importe l'agent que vous venez de créer !

# Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
load_dotenv(override=True)

def process_threat_alert(threat_data: dict):
    """
    Évalue une analyse de menace et décide s'il faut envoyer un e-mail d'alerte.
    """
    logging.info("🔍 Analyse de la menace en cours...")

    # 1. Vérifier le paramètre d'activation (Bouton ON/OFF)
    alerts_enabled = os.getenv("ENABLE_ALERTS", "true").lower() == "true"
    
    if not alerts_enabled:
        logging.warning("🛑 Les alertes e-mail sont DÉSACTIVÉES dans le .env. Aucun message ne sera envoyé.")
        return False

    # 2. Définir les règles de déclenchement (Sévérité High ou Critical)
    critical_severities = ["high", "critical"]
    severity = threat_data.get("severity", "low").lower()

    # 3. Appliquer les règles
    if severity in critical_severities:
        logging.error(f"🚨 MENACE {severity.upper()} DÉTECTÉE ! Déclenchement immédiat de l'alerte e-mail...")
        
        # 4. Préparer les données pour l'Agent E-mail
        initial_state = {
            "threat_report": threat_data.get("report", "Détails non fournis."),
            "recipient": os.getenv("ALERT_RECIPIENT", "test@example.com"),
            "email_subject": "", # L'IA de l'agent va le remplir
            "email_body": "",    # L'IA de l'agent va le remplir
            "status": ""
        }
        
        # 5. Appeler l'Agent E-mail
        result = email_agent.invoke(initial_state)
        
        if "success" in result["status"]:
            logging.info("✅ L'équipe de sécurité a été notifiée avec succès.")
        else:
            logging.error(f"❌ Échec de la notification : {result['status']}")
            
        return True
        
    else:
        # Si la menace est Faible (Low) ou Moyenne (Medium)
        logging.info(f"✅ Menace jugée mineure (Niveau: {severity.upper()}). Aucune alerte e-mail nécessaire.")
        return False