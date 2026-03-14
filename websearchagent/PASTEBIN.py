import requests
from bs4 import BeautifulSoup

# ─────────────────────────────────────
# MOTS-CLÉS À SURVEILLER
# ─────────────────────────────────────
MOTS_CLES_LEAK = [
    "password", "leak", "breach",
    "credentials", "database", "hack",
    "CVE", "exploit", "malware"
]

# ─────────────────────────────────────
# RÉCUPÉRER LES DERNIERS PASTES
# ─────────────────────────────────────
def get_derniers_pastes():
    url = "https://pastebin.com/archive"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    try:
        reponse = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(reponse.text, "html.parser")

        pastes = []
        for row in soup.select("table.maintable tr")[1:11]:  # 10 premiers
            cols = row.select("td")
            if cols:
                titre = cols[0].get_text().strip()
                lien  = "https://pastebin.com" + cols[0].find("a")["href"]
                pastes.append({
                    "titre": titre,
                    "lien" : lien,
                    "key"  : cols[0].find("a")["href"].strip("/")
                })

        return pastes

    except Exception as e:
        print(f"Erreur : {e}")
        return []

# ─────────────────────────────────────
# LIRE LE CONTENU D'UN PASTE
# ─────────────────────────────────────
def lire_paste(key: str) -> str:
    url = f"https://pastebin.com/raw/{key}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        reponse = requests.get(url, headers=headers, timeout=10)
        return reponse.text[:500]
    except Exception as e:
        return ""

# ─────────────────────────────────────
# SURVEILLER
# ─────────────────────────────────────
def surveiller_pastebin():
    print("👀 Surveillance Pastebin en cours...")

    pastes = get_derniers_pastes()
    print(f"  {len(pastes)} pastes trouvés")

    fuites = []
    for paste in pastes:
        contenu = lire_paste(paste["key"])
        contenu_lower = contenu.lower()

        mots_trouves = []
        for mot in MOTS_CLES_LEAK:
            if mot.lower() in contenu_lower:
                mots_trouves.append(mot)

        if mots_trouves:
            fuites.append({
                "source"      : "Pastebin",
                "titre"       : paste["titre"],
                "lien"        : paste["lien"],
                "resume"      : contenu[:200],
                "mots_trouves": mots_trouves,
            })
            print(f"  ⚠️  Fuite : {paste['titre'][:50]}")
            print(f"      Mots  : {mots_trouves}")

    return fuites


# ─────────────────────────────────────
# TESTER
# ─────────────────────────────────────
if __name__ == "__main__":
    fuites = surveiller_pastebin()
    print(f"\n✅ Total fuites détectées : {len(fuites)}")
    for f in fuites:
        print(f"\n[{f['source']}] {f['titre']}")
        print(f"  Lien → {f['lien']}")
        print(f"  Mots → {f['mots_trouves']}")