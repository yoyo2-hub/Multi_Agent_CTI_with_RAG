import requests
import json

def analyser_menace(article: dict) -> dict:

    prompt = f"""
Tu es un expert en cybersécurité CTI.
Analyse cette menace et réponds EXACTEMENT dans ce format :

CRITICITE: [CRITIQUE / ELEVEE / MOYENNE / FAIBLE]
TYPE: [ransomware / APT / vulnerability / breach / malware / autre]
RESUME: résumé en 1 phrase simple
VRAIE_MENACE: [OUI / NON]

Menace à analyser :
Titre  : {article['titre']}
Source : {article['source']}
Texte  : {article.get('resume', '')}
"""

    reponse = requests.post(
        "http://localhost:11435/api/chat",
        json={
            "model"   : "phi3",
            "messages": [{"role": "user", "content": prompt}],
            "stream"  : True
        },
        stream=True
    )

    # Lire ligne par ligne
    texte_complet = ""
    for ligne in reponse.iter_lines():
        if ligne:
            data = json.loads(ligne)
            if "message" in data:
                texte_complet += data["message"].get("content", "")

    return {
        "titre"       : article["titre"],
        "source"      : article["source"],
        "lien"        : article.get("lien", ""),
        "mots_trouves": article.get("mots_trouves", []),
        "analyse"     : texte_complet
    }


if __name__ == "__main__":

    article_test = {
        "source"      : "BleepingComputer",
        "titre"       : "CISA: BeyondTrust RCE flaw now exploited in ransomware attacks",
        "resume"      : "A critical RCE vulnerability in BeyondTrust exploited by ransomware groups",
        "mots_trouves": ["CVE", "vulnerability", "ransomware"],
    }

    print("🤖 Phi3 analyse la menace...")
    print()

    resultat = analyser_menace(article_test)

    print(f"[{resultat['source']}] {resultat['titre']}")
    print()
    print("── Analyse Phi3 ──")
    print(resultat["analyse"])