import requests
import feedparser
import re
import json
import time
import random
from bs4 import BeautifulSoup
from difflib import SequenceMatcher

# ─────────────────────────────────────
# CLÉS API
# ─────────────────────────────────────
OTX_API_KEY = "1552be520d74f388e1f0e7349c76a351020ecf8cdee408d2d8284350547307df"


# ─────────────────────────────────────
# ANONYMISATION — 3 SOLUTIONS
# ─────────────────────────────────────

# Solution 1 — User-Agents aléatoires
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/119.0.0.0",
]

def get_headers_aleatoires():
    return {
        "User-Agent"     : random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept"         : "text/html,application/xhtml+xml",
    }

# Solution 2 — Délai aléatoire
def attendre():
    delai = random.uniform(2, 5)
    print(f"  ⏳ Attente {round(delai, 1)} secondes...")
    time.sleep(delai)

# Solution 3 — Proxy Tor
PROXIES_TOR = {
    "http" : "socks5h://127.0.0.1:9150",
    "https": "socks5h://127.0.0.1:9150",
}

# ─────────────────────────────────────
# 1.1 RSS
# ─────────────────────────────────────
def collecter_rss():
    SOURCES = {
        "TheHackerNews"   : "https://feeds.feedburner.com/TheHackersNews",
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    }
    articles = []
    for nom, url in SOURCES.items():
        feed = feedparser.parse(url)
        for article in feed.entries[:5]:
            articles.append({
                "source" : nom,
                "titre"  : article.title,
                "lien"   : article.link,
                "resume" : article.summary,
            })
        attendre()                              # ✅ Solution 2
    return articles

# ─────────────────────────────────────
# 1.2 REDDIT
# ─────────────────────────────────────
def collecter_reddit():
    url = "https://www.reddit.com/r/netsec/hot.json?limit=5"
    
    # Attendre AVANT la requête
    attendre()
    
    try:
        response = requests.get(
            url,
            headers=get_headers_aleatoires(),
            timeout=30
        )
        
        # Vérifier que la réponse est bonne
        if response.status_code != 200:
            print(f"  ❌ Reddit erreur : {response.status_code}")
            return []
            
        if not response.text:
            print(f"  ❌ Reddit réponse vide")
            return []
        
        data = response.json()
        posts = []
        for post in data["data"]["children"]:
            info = post["data"]
            posts.append({
                "source" : "Reddit r/netsec",
                "titre"  : info["title"],
                "lien"   : info["url"],
                "resume" : info["selftext"][:300],
            })
        return posts
        
    except Exception as e:
        print(f"  ❌ Reddit erreur : {e}")
        return []

# ─────────────────────────────────────
# 1.2 STACKOVERFLOW
# ─────────────────────────────────────
def collecter_stackoverflow():
    url = "https://api.stackexchange.com/2.3/questions"
    params = {
        "order"   : "desc",
        "sort"    : "creation",
        "tagged"  : "security",
        "site"    : "stackoverflow",
        "pagesize": 5,
    }
    response = requests.get(
        url,
        params=params,
        headers=get_headers_aleatoires()       # ✅ Solution 1
    )
    attendre()                                 # ✅ Solution 2
    data = response.json()
    questions = []
    for item in data["items"]:
        questions.append({
            "source": "StackOverflow",
            "titre" : item["title"],
            "lien"  : item["link"],
            "resume": str(item["tags"]),
        })
    return questions

# ─────────────────────────────────────
# 1.3 ALIENVAULT OTX
# ─────────────────────────────────────
def collecter_otx():
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    response = requests.get(url, headers=headers)
    attendre()                                 # ✅ Solution 2
    data = response.json()
    menaces = []
    for pulse in data.get("results", [])[:5]:
        menaces.append({
            "source" : "AlienVault OTX",
            "titre"  : pulse["name"],
            "lien"   : f"https://otx.alienvault.com/pulse/{pulse['id']}",
            "resume" : pulse["description"][:300],
        })
    return menaces

# ─────────────────────────────────────
# 3.1 TOR
# ─────────────────────────────────────
def collecter_tor():
    resultats = []
    try:
        url = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/html/?q=CVE+2025+ransomware"
        reponse = requests.get(
            url,
            proxies=PROXIES_TOR,               # ✅ Solution 3
            headers=get_headers_aleatoires(),  # ✅ Solution 1
            timeout=60
        )
        attendre()                             # ✅ Solution 2
        soup = BeautifulSoup(reponse.text, "html.parser")
        for result in soup.select(".result__title")[:5]:
            titre = result.get_text().strip()
            if titre:
                resultats.append({
                    "source": "DuckDuckGo Tor",
                    "titre" : titre,
                    "lien"  : "",
                    "resume": "Résultat recherche CTI via Tor",
                })
    except Exception as e:
        print(f"  ❌ Erreur Tor : {e}")
    return resultats

# ─────────────────────────────────────
# 3.2 PASTEBIN
# ─────────────────────────────────────
def collecter_pastebin():
    url = "https://pastebin.com/archive"
    try:
        reponse = requests.get(
            url,
            headers=get_headers_aleatoires(), # ✅ Solution 1
            timeout=10
        )
        attendre()                            # ✅ Solution 2
        soup = BeautifulSoup(reponse.text, "html.parser")
        resultats = []
        for row in soup.select("table.maintable tr")[1:11]:
            cols = row.select("td")
            if cols:
                titre   = cols[0].get_text().strip()
                lien    = "https://pastebin.com" + cols[0].find("a")["href"]
                key     = cols[0].find("a")["href"].strip("/")
                contenu = requests.get(
                    f"https://pastebin.com/raw/{key}",
                    headers=get_headers_aleatoires(), # ✅ Solution 1
                    timeout=10
                ).text[:500]
                attendre()                    # ✅ Solution 2
                resultats.append({
                    "source" : "Pastebin",
                    "titre"  : titre,
                    "lien"   : lien,
                    "resume" : contenu[:200],
                })
        return resultats
    except Exception as e:
        print(f"  ❌ Erreur Pastebin : {e}")
        return []

# ─────────────────────────────────────
# 2.1 FILTRAGE
# ─────────────────────────────────────
MOTS_CLES = [
    "CVE", "vulnerability", "exploit", "zero-day", "patch",
    "malware", "ransomware", "backdoor", "trojan", "spyware",
    "attack", "breach", "hack", "phishing", "APT",
    "fortinet", "windows", "linux", "cisco", "android",
]

def filtrer(articles: list) -> list:
    articles_importants = []
    for article in articles:
        texte = article["titre"] + " " + article.get("resume", "")
        texte = texte.lower()
        mots_trouves = []
        for mot in MOTS_CLES:
            if re.search(mot.lower(), texte):
                mots_trouves.append(mot)
        if len(mots_trouves) >= 2:
            article["mots_trouves"] = mots_trouves
            articles_importants.append(article)
    return articles_importants

# ─────────────────────────────────────
# 2.3 DÉDUPLICATION
# ─────────────────────────────────────
def dedupliquer(articles: list) -> list:
    uniques = []
    for article in articles:
        titre = article["titre"].lower()
        est_doublon = False
        for unique in uniques:
            score = SequenceMatcher(None, titre, unique["titre"].lower()).ratio()
            if score >= 0.7:
                est_doublon = True
                print(f"  ⚠️  Doublon : {article['titre'][:50]}")
                break
        if not est_doublon:
            uniques.append(article)
    return uniques

# ─────────────────────────────────────
# 2.2 ANALYSE PHI3
# ─────────────────────────────────────
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
        "http://localhost:11435/api/chat",  # ✅ port correct
        json={
            "model"   : "phi3",
            "messages": [{"role": "user", "content": prompt}],
            "stream"  : True
        },
        stream=True
    )
    texte_complet = ""
    for ligne in reponse.iter_lines():
        if ligne:
            data = json.loads(ligne)
            if "message" in data:
                texte_complet += data["message"].get("content", "")
    article["analyse"] = texte_complet
    return article

def analyser_tout(articles: list) -> list:
    resultats = []
    for i, article in enumerate(articles):
        print(f"  🤖 Analyse {i+1}/{len(articles)} : {article['titre'][:50]}...")
        resultats.append(analyser_menace(article))
    return resultats

# ─────────────────────────────────────
# TOUT ASSEMBLER
# ─────────────────────────────────────
def collecter_tout():
    print("📡 Collecte RSS...")
    rss = collecter_rss()

    print("🕷️  Collecte Reddit...")
    reddit = collecter_reddit()

    print("🕷️  Collecte StackOverflow...")
    stackoverflow = collecter_stackoverflow()

    print("🔍 Collecte AlienVault OTX...")
    otx = collecter_otx()

    print("🧅 Collecte via Tor...")
    tor = collecter_tor()

    print("👀 Collecte Pastebin...")
    pastebin = collecter_pastebin()

    tous = rss + reddit + stackoverflow + otx + tor + pastebin

    print(f"\n✅ Total collecté : {len(tous)} éléments")
    print(f"   → RSS           : {len(rss)}")
    print(f"   → Reddit        : {len(reddit)}")
    print(f"   → StackOverflow : {len(stackoverflow)}")
    print(f"   → OTX           : {len(otx)}")
    print(f"   → Tor           : {len(tor)}")
    print(f"   → Pastebin      : {len(pastebin)}")

    print("\n🔎 Filtrage en cours...")
    filtres = filtrer(tous)
    print(f"✅ Après filtrage : {len(filtres)} éléments")

    print("\n🧹 Déduplication en cours...")
    uniques = dedupliquer(filtres)
    print(f"✅ Après déduplication : {len(uniques)} éléments uniques")

    print("\n🤖 Analyse Phi3 en cours...")
    analyses = analyser_tout(uniques)
    print(f"✅ Analyse terminée !")

    return analyses


# ── Lancer ──
if __name__ == "__main__":
    donnees = collecter_tout()
    print("\n── Résultat final ──")
    for d in donnees:
        print(f"\n[{d['source']}] {d['titre']}")
        print(f"  Mots   → {d.get('mots_trouves', [])}")
        print(f"  Analyse→ {d.get('analyse', '')[:150]}")