import json
import os
from datetime import datetime

# ─────────────────────────────────────
# FICHIER JSON
# ─────────────────────────────────────
FICHIER_JSON = "e:/RAG_CTI/websearchagent/cti_menaces.json"

# ─────────────────────────────────────
# FORMATER UNE MENACE
# ─────────────────────────────────────
def formater_menace(menace: dict, index: int) -> dict:

    analyse     = menace.get("analyse", "")
    criticite   = "INCONNUE"
    type_menace = "autre"
    resume_phi3 = ""

    for ligne in analyse.split("\n"):
        if "CRITICITE:" in ligne:
            criticite   = ligne.replace("CRITICITE:", "").strip()
        if "TYPE:" in ligne:
            type_menace = ligne.replace("TYPE:", "").strip()
        if "RESUME:" in ligne:
            resume_phi3 = ligne.replace("RESUME:", "").strip()

    # ── TEXT — même format que ton projet ──
    text_formatted = (
        f"[POST_ID: {index}] | "
        f"TYPE: POST | "
        f"CHANNEL: {menace.get('source', '')} | "
        f"CONTENT: {menace.get('titre', '')} "
        f"{menace.get('resume', '')[:200]}"
    )

    # ── METADATA — même format que ton projet ──
    metadata = {
        "url"             : menace.get("lien", ""),
        "date"            : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "views"           : None,
        "forwards"        : None,
        "replies"         : None,
        "out"             : False,
        "mentioned"       : False,
        "media_unread"    : False,
        "silent"          : False,
        "post"            : True,
        "from_scheduled"  : False,
        "legacy"          : False,
        "edit_hide"       : False,
        "pinned"          : False,
        "noforwards"      : False,
        "peer_channel"    : None,
        "from_id_user"    : None,
        "via_bot_id"      : None,
        "reply_to_msg_id" : None,
        "reply_to_scheduled": None,
        "forum_topic"     : None,
        "media_photo_id"  : None,
        "reply_markup"    : None,
        "edit_date"       : None,
        "post_author"     : None,
        "grouped_id"      : None,
        "ttl_period"      : None,
        # ── Champs CTI spécifiques ──
        "category"        : criticite.lower(),
        "doc_type"        : "cti_threat",
        "channel_name"    : menace.get("source", ""),
        "recovered"       : False,
        "mots_trouves"    : menace.get("mots_trouves", []),
        "criticite"       : criticite,
        "type_menace"     : type_menace,
        "resume_phi3"     : resume_phi3,
        "analyse_complete": analyse,
    }

    return {
        "text"    : text_formatted,
        "metadata": metadata
    }

# ─────────────────────────────────────
# SAUVEGARDER DANS JSON
# ─────────────────────────────────────
def sauvegarder_json(menaces: list):
    print("💾 Sauvegarde dans JSON...")

    # Charger les données existantes si le fichier existe
    donnees_existantes = []
    if os.path.exists(FICHIER_JSON):
        with open(FICHIER_JSON, "r", encoding="utf-8") as f:
            donnees_existantes = json.load(f)

    # Formater les nouvelles menaces
    nouvelles_menaces = []
    for i, menace in enumerate(menaces):
        index = len(donnees_existantes) + i + 1
        menace_formatee = formater_menace(menace, index)
        nouvelles_menaces.append(menace_formatee)
        print(f"  ✅ Sauvegardé : {menace['titre'][:50]}")

    # Ajouter les nouvelles menaces
    toutes_menaces = donnees_existantes + nouvelles_menaces

    # Sauvegarder dans le fichier JSON
    with open(FICHIER_JSON, "w", encoding="utf-8") as f:
        json.dump(toutes_menaces, f, ensure_ascii=False, indent=4)

    print(f"✅ {len(nouvelles_menaces)} menaces sauvegardées !")
    print(f"✅ Total dans JSON : {len(toutes_menaces)} menaces")


# ─────────────────────────────────────
# TESTER
# ─────────────────────────────────────
if __name__ == "__main__":
    menaces_test = [
        {
            "source"      : "TheHackerNews",
            "titre"       : "Critical CVE-2025 Found in Windows",
            "lien"        : "https://thehackernews.com/...",
            "resume"      : "A critical vulnerability found in Windows",
            "mots_trouves": ["CVE", "exploit", "windows"],
            "analyse"     : "CRITICITE: CRITIQUE\nTYPE: vulnerability\nRESUME: Faille critique Windows exploitée\nVRAIE_MENACE: OUI"
        },
        {
            "source"      : "AlienVault OTX",
            "titre"       : "KONNI PowerShell Backdoors",
            "lien"        : "https://otx.alienvault.com/...",
            "resume"      : "North Korea APT group using backdoor",
            "mots_trouves": ["backdoor", "APT", "phishing"],
            "analyse"     : "CRITICITE: ELEVEE\nTYPE: APT\nRESUME: Groupe nord-coréen utilise backdoor PowerShell\nVRAIE_MENACE: OUI"
        }
    ]

    sauvegarder_json(menaces_test)