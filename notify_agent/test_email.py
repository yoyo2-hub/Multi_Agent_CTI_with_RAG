from agent_email import email_agent
import os
from dotenv import load_dotenv

load_dotenv()

# Simulation d'un rapport de menace sorti de votre RAG
test_report = """
Rapport CTI - 22/02/2026
Menace détectée : Tentative de phishing ciblée (Spear Phishing).
Sévérité : Moyenne.
Indicateurs de compromission (IOC) : IP 192.168.1.100 suspecte.
Action recommandée : Bloquer l'IP au niveau du pare-feu.
"""

# Initialisation de l'état
initial_state = {
    "threat_report": test_report,
    "recipient": os.getenv("DEFAULT_RECIPIENT", "admin@test.com"),
    "email_subject": "",
    "email_body": "",
    "status": ""
}

# Lancement de l'agent LangGraph
print("Lancement de l'agent Email...")
result = email_agent.invoke(initial_state)

print("\n--- Résultat final de l'état ---")
print(f"Sujet : {result['email_subject']}")
print(f"Statut d'envoi : {result['status']}")