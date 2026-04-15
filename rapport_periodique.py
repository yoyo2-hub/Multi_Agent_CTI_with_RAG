import os
import datetime
from collections import Counter
import schedule
import time

def generer_rapport_markdown(menaces, periode="Quotidien", profil_audience="management"):
    """
    Génère un rapport Markdown adapté à l'audience ciblée (management ou technique).
    """
    print(f"\n📊 Génération du rapport {periode} [Format: {profil_audience.upper()}] en cours...")
    
    total_menaces = len(menaces)
    severites = Counter([m.get("severity", "low").lower() for m in menaces])
    date_jour = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # --- EN-TÊTE COMMUN ---
    md_content = f"# 🛡️ Rapport CTI {periode} - Vue {profil_audience.capitalize()}\n\n"
    md_content += f"**Date de génération :** {date_jour}\n"
    md_content += f"**Total des menaces :** {total_menaces}\n\n"
    
    # --- FORMAT 1 : MANAGEMENT (Résumé exécutif et Impact) ---
    if profil_audience.lower() == "management":
        md_content += "## 📈 Résumé Exécutif\n"
        md_content += f"- 🔴 **Critique :** {severites.get('critical', 0)} | 🟠 **Élevée :** {severites.get('high', 0)} | 🟡 **Moyenne :** {severites.get('medium', 0)} | 🟢 **Faible :** {severites.get('low', 0)}\n\n"
        
        md_content += "## 💼 Impact Business des Menaces Principales\n"
        for m in menaces:
            if m.get("severity", "low").lower() in ["high", "critical"]:
                md_content += f"### {m.get('title')}\n"
                md_content += f"- **Niveau de Risque :** {m.get('severity').upper()}\n"
                md_content += f"- **Impact potentiel :** {m.get('impact_business', 'Non évalué.')}\n\n"
                
    # --- FORMAT 2 : TECHNIQUE (Détails, IOCs, MITRE ATT&CK) ---
    elif profil_audience.lower() == "technique":
        md_content += "## 🔬 Répartition Détaillée par Sévérité\n"
        md_content += f"- 🔴 **CRITICAL :** {severites.get('critical', 0)}\n"
        md_content += f"- 🟠 **HIGH :** {severites.get('high', 0)}\n"
        md_content += f"- 🟡 **MEDIUM :** {severites.get('medium', 0)}\n"
        md_content += f"- 🟢 **LOW :** {severites.get('low', 0)}\n\n"
        
        md_content += "## 🛠️ Analyse Technique et Indicateurs de Compromission (IOC)\n"
        for m in menaces:
            md_content += f"### {m.get('title')} ({m.get('severity').upper()})\n"
            md_content += f"- **Date de détection :** {m.get('date')}\n"
            md_content += f"- **Techniques MITRE ATT&CK :** `{m.get('mitre', 'N/A')}`\n"
            md_content += f"- **IOCs identifiés :** `{m.get('ioc', 'Aucun')}`\n\n"
            
    md_content += "---\n*Rapport généré automatiquement par le système RAG CTI.*"
    
    # Sauvegarde
    if not os.path.exists("rapports"):
        os.makedirs("rapports")
        
    # On ajoute le nom du profil dans le nom du fichier pour ne pas les mélanger
    nom_fichier = f"rapports/Rapport_{profil_audience.capitalize()}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    
    with open(nom_fichier, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    print(f"✅ Rapport sauvegardé : {nom_fichier}")
    return nom_fichier                                                              