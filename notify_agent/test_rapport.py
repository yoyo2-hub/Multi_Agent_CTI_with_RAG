import schedule
import time
# 1. On importe la VRAIE fonction qui existe dans votre fichier !
from rapport_periodique import generer_rapport_markdown

print("\n=== DÉBUT DU TEST DU PLANIFICATEUR DE RAPPORTS ===\n")

# 2. On crée de fausses données (notre fausse boîte de dossiers de l'Agent 2) pour que le rapport ait quelque chose à écrire.
fausses_menaces = [
    {"title": "Tentative de Phishing", "severity": "high", "impact_business": "Vol de mots de passe de la direction", "date": "2026-03-18", "mitre": "T1566", "ioc": "IP: 192.168.1.10"},
    {"title": "Ransomware bloqué", "severity": "critical", "impact_business": "Paralysie du serveur financier", "date": "2026-03-18", "mitre": "T1486", "ioc": "Fichier: virus.exe"}
]

# 3. On crée la tâche que le planificateur va lancer toutes les 5 secondes
def ma_tache_de_test():
    print("\n⏰ Tic Tac ! Le planificateur se réveille !")
    # On demande au Journaliste de faire son travail avec nos fausses données
    generer_rapport_markdown(fausses_menaces, periode="Quotidien", profil_audience="management")
    generer_rapport_markdown(fausses_menaces, periode="Quotidien", profil_audience="technique")

print("Dans la vraie vie, ce script tournerait en arrière-plan et déclencherait le rapport tous les jours à 23h59.")
print("Pour notre environnement de dev, nous allons le configurer pour se déclencher toutes les 5 secondes.\n")

# Configuration de la simulation : exécution toutes les 5 secondes
schedule.every(5).seconds.do(ma_tache_de_test)

# On force une première exécution immédiate pour voir le résultat tout de suite
ma_tache_de_test()

print("\n⏳ Le planificateur est actif. Attendez quelques secondes pour voir les prochaines exécutions...")
print("⚠️ Appuyez sur Ctrl+C dans ce terminal pour arrêter le test.\n")

try:
    while True:
        schedule.run_pending()
        time.sleep(1)
except KeyboardInterrupt:
    print("\n🛑 Test arrêté par l'utilisateur.")
    print("=== FIN DU TEST ===")