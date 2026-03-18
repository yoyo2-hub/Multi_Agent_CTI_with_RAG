import schedule
import time
from rapport_periodique import tache_automatique_quotidienne

print("\n=== DÉBUT DU TEST DU PLANIFICATEUR DE RAPPORTS ===\n")

print("Dans la vraie vie, ce script tournerait en arrière-plan et déclencherait le rapport tous les jours à 23h59.")
print("Pour notre environnement de dev, nous allons le configurer pour se déclencher toutes les 5 secondes.\n")

# Configuration de la simulation : exécution toutes les 5 secondes
schedule.every(5).seconds.do(tache_automatique_quotidienne)

# On force une première exécution immédiate pour voir le résultat tout de suite
tache_automatique_quotidienne()

print("\n⏳ Le planificateur est actif. Attendez quelques secondes pour voir les prochaines exécutions...")
print("⚠️ Appuyez sur Ctrl+C dans ce terminal pour arrêter le test.\n")

try:
    while True:
        schedule.run_pending()
        time.sleep(1)
except KeyboardInterrupt:
    print("\n🛑 Test arrêté par l'utilisateur.")
    print("=== FIN DU TEST ===")