import requests
import time
import random
from bs4 import BeautifulSoup

# ─────────────────────────────────────
# SOLUTION 1 — USER AGENTS
# ─────────────────────────────────────
# Simuler différents navigateurs
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Chrome/119.0.0.0",
]

def get_headers_aleatoires():
    # Choisir un User-Agent au hasard
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml",
    }


# ─────────────────────────────────────
# SOLUTION 2 — DÉLAIS ALÉATOIRES
# ─────────────────────────────────────
def attendre():
    # Attendre entre 2 et 5 secondes
    delai = random.uniform(2, 5)
    print(f"  ⏳ Attente {round(delai, 1)} secondes...")
    time.sleep(delai)


# ─────────────────────────────────────
# SOLUTION 3 — ROTATION TOR
# ─────────────────────────────────────
PROXIES_TOR = {
    "http" : "socks5h://127.0.0.1:9150",
    "https": "socks5h://127.0.0.1:9150",
}

def requete_anonyme(url: str, via_tor: bool = False) -> requests.Response:
    headers = get_headers_aleatoires()

    if via_tor:
        reponse = requests.get(
            url,
            headers=headers,
            proxies=PROXIES_TOR,
            timeout=60
        )
    else:
        reponse = requests.get(
            url,
            headers=headers,
            timeout=30
        )

    # Attendre après chaque requête
    attendre()

    return reponse


# ─────────────────────────────────────
# TESTER
# ─────────────────────────────────────
if __name__ == "__main__":

    # Test sans Tor
    print("🔍 Test sans Tor...")
    r = requete_anonyme("https://httpbin.org/ip")
    print(f"  Mon IP normale : {r.json()['origin']}")

    # Test avec Tor
    print("🧅 Test avec Tor...")
    r = requete_anonyme("https://httpbin.org/ip", via_tor=True)
    print(f"  Mon IP via Tor : {r.json()['origin']}")