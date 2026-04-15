import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import TypedDict
from dotenv import load_dotenv

# Cela demande à Python de chercher le fichier .env dans tous les dossiers parents
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
load_dotenv("src/.env")
# ---------------------------------------------------------
# 1. Définition du State
# ---------------------------------------------------------
class EmailState(TypedDict):
    threat_report: str
    recipient: str
    email_subject: str
    email_body: str
    status: str

# ---------------------------------------------------------
# 2. Définition des Nodes
# ---------------------------------------------------------
def draft_email_node(state: EmailState):
    """Génère le sujet et le corps de l'e-mail via le LLM."""
    logging.info("Création du brouillon de l'e-mail...")
    llm = ChatOllama(model="phi3.5", base_url="http://127.0.0.1:11435", temperature=0.1)    
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", "Tu es un agent de communication en cybersécurité. "
                   "Lis le rapport de menace suivant et rédige un e-mail court. "
                   "Réponds EXACTEMENT dans ce format :\n"
                   "SUJET: [Ton sujet ici]\n"
                   "CORPS:\n[Ton corps d'e-mail ici]"),
        ("user", "{report}")
    ])
    
    chain = prompt | llm
    response = chain.invoke({"report": state["threat_report"]})
    content = response.content
    
    try:
        # ✨ ASTUCE : On gère le cas où l'IA répond en anglais ("SUBJECT:" au lieu de "SUJET:")
        content_clean = content.replace("SUBJECT:", "SUJET:").replace("BODY:", "CORPS:")
        
        subject_part = content_clean.split("SUJET:")[1].split("CORPS:")[0].strip()
        body_part = content_clean.split("CORPS:")[1].strip()
    except IndexError:
        subject_part = "Alerte de menace CTI"
        body_part = content
        
    return {"email_subject": subject_part, "email_body": body_part}

def send_email_node(state: EmailState):
    """Envoie l'e-mail via SMTP."""
    logging.info(f"Tentative d'envoi de l'e-mail à {state['recipient']}...")
    
    msg = MIMEMultipart()
    msg['From'] = os.getenv("Ranim Bouguila", "ranim.bouguila@enis.tn").strip()
    msg['To'] = state['recipient'].strip()
    msg['Subject'] = state['email_subject']
    msg.attach(MIMEText(state['email_body'], 'plain'))

    try:
        serveur = os.getenv("SMTP_SERVER", "").strip()
        port = int(os.getenv("SMTP_PORT", "587").strip())
        user = os.getenv("SMTP_USER", "").strip()
        mdp = os.getenv("SMTP_PASSWORD", "").strip()

        server = smtplib.SMTP(serveur, port)
        # ✨ ASTUCE : Le mode debug est désactivé pour garder un terminal propre !
        # server.set_debuglevel(1) 
        
        server.starttls()
        server.login(user, mdp)
        server.send_message(msg)
        server.quit()
        
        logging.info("✅ E-mail envoyé avec succès !")
        return {"status": "success"}
    except Exception as e:
        logging.error(f"❌ Erreur lors de l'envoi de l'e-mail : {e}")
        return {"status": f"error: {str(e)}"}

# ---------------------------------------------------------
# 3. Construction du Graphe LangGraph
# ---------------------------------------------------------
workflow = StateGraph(EmailState)
workflow.add_node("draft", draft_email_node)
workflow.add_node("send", send_email_node)
workflow.set_entry_point("draft")
workflow.add_edge("draft", "send")
workflow.add_edge("send", END)
email_agent = workflow.compile()                                                        