import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ─────────────────────────────────────
# CONFIGURATION EMAIL
# ─────────────────────────────────────
EMAIL_EXPEDITEUR = "emnaghorbel56@gmail.com"
EMAIL_MOT_PASSE  = "phlk bolj wibp zvwb"
EMAIL_DESTINATAIRE = "emnaghorbel65@gmail.com"

# ─────────────────────────────────────
# ENVOYER UN EMAIL
# ─────────────────────────────────────
def envoyer_email(menace: dict):
    # Créer le message
    msg = MIMEMultipart()
    msg["From"]    = EMAIL_EXPEDITEUR
    msg["To"]      = EMAIL_DESTINATAIRE
    msg["Subject"] = f"🚨 Alerte CTI : {menace['titre'][:50]}"

    # Corps du message
    corps = f"""
🚨 ALERTE CYBERMENACE DÉTECTÉE

Source   : {menace['source']}
Titre    : {menace['titre']}
Lien     : {menace.get('lien', 'N/A')}
Mots-clés: {menace.get('mots_trouves', [])}

Analyse Phi3 :
{menace.get('analyse', 'Pas d analyse disponible')}
"""
    msg.attach(MIMEText(corps, "plain"))

    # Envoyer via Gmail
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_EXPEDITEUR, EMAIL_MOT_PASSE)
        server.send_message(msg)
        server.quit()
        print(f"  ✅ Email envoyé : {menace['titre'][:50]}")
    except Exception as e:
        print(f"  ❌ Erreur email : {e}")

# ─────────────────────────────────────
# ENVOYER ALERTES POUR MENACES CRITIQUES
# ─────────────────────────────────────
def envoyer_alertes(menaces: list):
    print("📧 Envoi des alertes email...")
    alertes_envoyees = 0

    for menace in menaces:
        analyse = menace.get("analyse", "")

        # Envoyer seulement pour CRITIQUE et ELEVEE
        if "CRITIQUE" in analyse or "ELEVEE" in analyse:
            envoyer_email(menace)
            alertes_envoyees += 1

    print(f"✅ {alertes_envoyees} alertes envoyées !")


# ─────────────────────────────────────
# TESTER
# ─────────────────────────────────────
if __name__ == "__main__":
    menace_test = {
        "source"      : "TheHackerNews",
        "titre"       : "Critical CVE-2025 Found in Windows",
        "lien"        : "https://thehackernews.com/...",
        "mots_trouves": ["CVE", "exploit", "windows"],
        "analyse"     : "CRITICITE: CRITIQUE\nTYPE: vulnerability\nRESUME: Faille critique Windows\nVRAIE_MENACE: OUI"
    }

    print("📧 Test envoi email...")
    envoyer_email(menace_test)