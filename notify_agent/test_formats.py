from rapport_periodique import generer_rapport_markdown

print("\n=== TEST DES PROFILS D'AUDIENCE (MANAGEMENT vs TECHNIQUE) ===\n")

# 1. On crée UNE SEULE base de données enrichie
menaces_enrichies = [
    {
        "title": "Tentative de Phishing ciblé", 
        "severity": "High", 
        "date": "2026-02-22",
        "ioc": "IP: 192.168.1.100, URL: login-update-secure.com",
        "mitre": "T1566.002 (Spearphishing Link)",
        "impact_business": "Risque élevé de vol d'identifiants administrateur et fuite de données."
    },
    {
        "title": "Ransomware bloqué (Serveur Finance)", 
        "severity": "Critical", 
        "date": "2026-02-22",
        "ioc": "Hash SHA256: 7d4e5f8a..., Fichier: update_v2.exe",
        "mitre": "T1486 (Data Encrypted for Impact)",
        "impact_business": "Paralysie potentielle du service facturation. Perte financière évitée."
    },
    {
        "title": "Scan de vulnérabilités externe", 
        "severity": "Low", 
        "date": "2026-02-22",
        "ioc": "IP: 45.33.22.11",
        "mitre": "T1595.002 (Active Scanning: Vulnerability Scanning)",
        "impact_business": "Bruit de fond habituel d'Internet. Aucun impact direct."
    }
]

# 2. On génère le format MANAGEMENT (Directeur)
print("1️⃣ Génération pour le Directeur (Impact Business) :")
generer_rapport_markdown(menaces_enrichies, periode="Quotidien", profil_audience="management")

# 3. On génère le format TECHNIQUE (Analyste SOC)
print("\n2️⃣ Génération pour l'Équipe SOC (IOC & MITRE) :")
generer_rapport_markdown(menaces_enrichies, periode="Quotidien", profil_audience="technique")

print("\n=== FIN DU TEST ===")
print("Allez vérifier les deux nouveaux fichiers créés dans le dossier 'rapports' !")