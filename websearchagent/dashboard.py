import streamlit as st
import sys
sys.path.append("e:/RAG_CTI/websearchagent")
from infrastructure_collecte import collecter_tout

# ─────────────────────────────────────
# CONFIG PAGE
# ─────────────────────────────────────
st.set_page_config(
    page_title="CTI Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ─────────────────────────────────────
# TITRE
# ─────────────────────────────────────
st.title("🛡️ CTI Threat Intelligence Dashboard")
st.markdown("Surveillance des cybermenaces en temps réel")

# ─────────────────────────────────────
# BOUTON COLLECTER
# ─────────────────────────────────────
if st.button("🔄 Lancer la collecte"):
    with st.spinner("Collecte en cours..."):
        menaces = collecter_tout()
        st.session_state["menaces"] = menaces
        st.success(f"✅ {len(menaces)} menaces collectées !")

# ─────────────────────────────────────
# AFFICHER LES MENACES
# ─────────────────────────────────────
if "menaces" in st.session_state:
    menaces = st.session_state["menaces"]

    # Compter par criticité
    critique = [m for m in menaces if "CRITIQUE" in m.get("analyse", "")]
    elevee   = [m for m in menaces if "ELEVEE"   in m.get("analyse", "")]
    moyenne  = [m for m in menaces if "MOYENNE"  in m.get("analyse", "")]

    # Statistiques
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total",    len(menaces))
    col2.metric("🔴 Critique", len(critique))
    col3.metric("🟠 Elevée",   len(elevee))
    col4.metric("🟡 Moyenne",  len(moyenne))

    st.divider()

    # Filtrer par criticité
    filtre = st.selectbox(
        "Filtrer par criticité",
        ["Toutes", "CRITIQUE", "ELEVEE", "MOYENNE", "FAIBLE"]
    )

    # Afficher les menaces
    for menace in menaces:
        analyse = menace.get("analyse", "")

        # Appliquer le filtre
        if filtre != "Toutes" and filtre not in analyse:
            continue

        # Couleur selon criticité
        if "CRITIQUE" in analyse:
            couleur = "🔴"
        elif "ELEVEE" in analyse:
            couleur = "🟠"
        elif "MOYENNE" in analyse:
            couleur = "🟡"
        else:
            couleur = "🟢"

        # Afficher la menace
        with st.expander(f"{couleur} [{menace['source']}] {menace['titre']}"):
            col1, col2 = st.columns(2)
            col1.write(f"**Source** : {menace['source']}")
            col2.write(f"**Mots-clés** : {menace.get('mots_trouves', [])}")

            if menace.get("lien"):
                st.write(f"**Lien** : {menace['lien']}")

            st.divider()
            st.write("**Analyse Phi3 :**")
            st.code(analyse)