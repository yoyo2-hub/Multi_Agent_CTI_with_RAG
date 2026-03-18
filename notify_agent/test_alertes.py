import os
from alert_manager import process_threat_alert

print("\n=== DÉBUT DES TESTS DES ALERTES AUTOMATISÉES ===\n")

# Simulation 1 : Menace mineure (Ne doit PAS envoyer d'e-mail)
print("--- SCÉNARIO 1 : Menace Mineure (Low) ---")
menace_mineure = {
    "severity": "Low",
    "report": "Un utilisateur a tapé le mauvais mot de passe 2 fois. Rien de grave."
}
process_threat_alert(menace_mineure)


# Simulation 2 : Menace critique (DOIT envoyer un e-mail)
print("\n--- SCÉNARIO 2 : Menace Critique (Critical) ---")
menace_critique = {
    "severity": "Critical",
    "report": "Une attaque par Ransomware est en cours de déploiement sur le serveur principal (IP: 10.0.0.5). Les fichiers commencent à être chiffrés. Intervention humaine requise immédiatement."
}
process_threat_alert(menace_critique)


# Simulation 3 : Menace critique, mais système désactivé (Ne doit PAS envoyer d'e-mail)
print("\n--- SCÉNARIO 3 : Système d'alerte désactivé ---")
# On force la désactivation en modifiant la variable d'environnement juste pour ce test
os.environ["ENABLE_ALERTS"] = "false" 
process_threat_alert(menace_critique)

print("\n=== FIN DES TESTS ===")