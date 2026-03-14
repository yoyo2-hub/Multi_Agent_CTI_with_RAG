import requests
from bs4 import BeautifulSoup

# ─────────────────────────────────────
# CONNEXION TOR
# ─────────────────────────────────────
proxies = {
    "http" : "socks5h://127.0.0.1:9150",
    "https": "socks5h://127.0.0.1:9150"
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# ─────────────────────────────────────
# COLLECTER VIA TOR
# ─────────────────────────────────────
def collecter_via_tor():
    resultats = []

    # Source 1 — DuckDuckGo .onion
    # Chercher des menaces CTI
    print("🔍 Recherche CTI via Tor...")
    try:
        url = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html/?q=CVE+2025+ransomware"
        reponse = requests.get(
            url,
            proxies=proxies,
            headers=headers,
            timeout=60
        )
        soup = BeautifulSoup(reponse.text, "html.parser")
        
        # Extraire les résultats
        for result in soup.select(".result__title")[:5]:
            titre = result.get_text().strip()
            if titre:
                resultats.append({
                    "source": "DuckDuckGo Tor",
                    "titre" : titre,
                    "lien"  : "",
                    "resume": "Résultat recherche Tor CTI"
                })
                print(f"  ✅ Trouvé : {titre[:60]}")

    except Exception as e:
        print(f"  ❌ Erreur DuckDuckGo Tor : {e}")

    return resultats


# ─────────────────────────────────────
# TESTER
# ─────────────────────────────────────
if __name__ == "__main__":
    print("🧅 Connexion via Tor...")
    resultats = collecter_via_tor()
    print(f"\n✅ Total trouvé : {len(resultats)} éléments")
    for r in resultats:
        print(f"  [{r['source']}] {r['titre']}")