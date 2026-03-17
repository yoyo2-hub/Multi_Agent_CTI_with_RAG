# ─────────────────────────────────────────────
# ORCHESTRATEUR CTI — LangGraph + LangSmith
# ─────────────────────────────────────────────

import os
import sys
import json
from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path
from typing import TypedDict

from langgraph.graph import StateGraph, END
from langsmith import traceable

from langgraph.graph import StateGraph, END
from typing import TypedDict
from dotenv import load_dotenv
import os

# # Charger le fichier .env
# load_dotenv(dotenv_path="C:/Users/Hamza/Desktop/emna/RAG_CTI/test/.env")

# # Configurer LangSmith depuis le .env
# os.environ["LANGCHAIN_TRACING_V2"] = "true"
# os.environ["LANGCHAIN_API_KEY"]    = os.getenv("LANGCHAIN_API_KEY")
# os.environ["LANGCHAIN_PROJECT"]    = os.getenv("LANGCHAIN_PROJECT")

# print("✅ LangSmith configuré !")
# print(f"   Projet : {os.getenv('LANGCHAIN_PROJECT')}")
# print(f"   URL    : https://smith.langchain.com")

# ─────────────────────────────────────────────
# CHEMINS DES 3 AGENTS
# ─────────────────────────────────────────────

BASE = "C:/Users/Hamza/Desktop/emna/RAG_CTI"

sys.path.append(os.path.join(BASE, "websearchagent"))
sys.path.append(os.path.join(BASE, "cti_agent"))
sys.path.append(os.path.join(BASE, "notify_agent"))

# ─────────────────────────────────────────────
# IMPORTS — fonction main() de chaque agent
# ─────────────────────────────────────────────

from infrastructure_collecte import collecter_tout as main_websearch
from agent_analyse           import main as main_cti  # À adapter selon le nom de votre fichier et fonction principale
from notificationsemail      import main as main_notify # À adapter selon le nom de votre fichier et fonction principale

print("✅ 3 agents importés !")

# ─────────────────────────────────────────────
# STATE
# ─────────────────────────────────────────────

class CTIState(TypedDict):
    menaces_brutes    : list
    menaces_analysees : list
    priorites         : list
    rapport           : str
    alertes_envoyees  : int
    messages          : list

# ─────────────────────────────────────────────
# AGENT 1 — Web Search Agent
# ─────────────────────────────────────────────

@traceable(name="Web Search Agent")
def web_search_agent(state: CTIState) -> CTIState:
    print("\n" + "="*60)
    print("🔍 AGENT 1 — Web Search Agent")
    print("="*60)

    # Appel de la fonction main() de l'agent 1
    menaces = main_websearch()

    state["menaces_brutes"] = menaces
    state["messages"].append({
        "agent"    : "web_search_agent",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total"    : len(menaces),
        "statut"   : "✅ terminé"
    })

    print(f"✅ Agent 1 terminé : {len(menaces)} menaces collectées")
    return state

# ─────────────────────────────────────────────
# AGENT 2 — CTI Agent
# ─────────────────────────────────────────────

@traceable(name="CTI Agent")
def cti_agent(state: CTIState) -> CTIState:
    print("\n" + "="*60)
    print("🧠 AGENT 2 — CTI Agent")
    print("="*60)

    menaces_brutes = state["menaces_brutes"]
    print(f"   Reçu de Agent 1 : {len(menaces_brutes)} menaces")

    # Appel de la fonction main() de l'agent 2
    # On lui passe les menaces brutes de l'agent 1
    analyses = main_cti(menaces_brutes)

    # Priorisation
    priorites = []
    for m in analyses:
        criticite = m.get("criticite", "INCONNUE")
        priorite  = 1 if "CRITIQUE" in criticite else \
                    2 if "ELEVEE"   in criticite else \
                    3 if "MOYENNE"  in criticite else 4
        m["priorite"] = priorite
        priorites.append(m)

    priorites.sort(key=lambda x: x["priorite"])

    state["menaces_analysees"] = analyses
    state["priorites"]         = priorites
    state["messages"].append({
        "agent"    : "cti_agent",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total"    : len(analyses),
        "critique" : len([m for m in analyses if m.get("criticite") == "CRITIQUE"]),
        "elevee"   : len([m for m in analyses if m.get("criticite") == "ELEVEE"]),
        "statut"   : "✅ terminé"
    })

    print(f"✅ Agent 2 terminé : {len(analyses)} menaces analysées")
    return state

# ─────────────────────────────────────────────
# AGENT 3 — Notify Agent
# ─────────────────────────────────────────────

@traceable(name="Notify Agent")
def notify_agent(state: CTIState) -> CTIState:
    print("\n" + "="*60)
    print("📢 AGENT 3 — Notify Agent")
    print("="*60)

    priorites = state["priorites"]
    print(f"   Reçu de Agent 2 : {len(priorites)} menaces")

    # Appel de la fonction main() de l'agent 3
    # On lui passe les menaces analysées et priorisées
    rapport, alertes = main_notify(priorites)

    # Sauvegarder les logs inter-agents
    logs_path = os.path.join(BASE, "websearchagent/logs_agents.json")
    with open(logs_path, "w", encoding="utf-8") as f:
        json.dump(state["messages"], f, ensure_ascii=False, indent=4)
    print(f"   ✅ Logs sauvegardés → {logs_path}")

    state["rapport"]          = rapport
    state["alertes_envoyees"] = alertes
    state["messages"].append({
        "agent"    : "notify_agent",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alertes"  : alertes,
        "statut"   : "✅ terminé"
    })

    print(f"✅ Agent 3 terminé : {alertes} alertes envoyées")
    return state

# ─────────────────────────────────────────────
# WORKFLOW LANGGRAPH
# ─────────────────────────────────────────────

def creer_workflow():
    graph = StateGraph(CTIState)

    graph.add_node("web_search", web_search_agent)
    graph.add_node("cti_agent",  cti_agent)
    graph.add_node("notify",     notify_agent)

    graph.set_entry_point("web_search")

    graph.add_edge("web_search", "cti_agent")
    graph.add_edge("cti_agent",  "notify")
    graph.add_edge("notify",     END)

    return graph.compile()

# ─────────────────────────────────────────────
# LANCER
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 LANCEMENT ORCHESTRATEUR CTI MULTI-AGENT")
    print(f"   Heure    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   LangSmith: https://smith.langchain.com")
    print("="*60)

    app = creer_workflow()

    etat_initial = {
        "menaces_brutes"   : [],
        "menaces_analysees": [],
        "priorites"        : [],
        "rapport"          : "",
        "alertes_envoyees" : 0,
        "messages"         : []
    }

    resultat = app.invoke(etat_initial)

    # Résumé final
    print("\n" + "="*60)
    print("🎉 ORCHESTRATION TERMINÉE !")
    print("="*60)
    print(f"   Menaces collectées : {len(resultat['menaces_brutes'])}")
    print(f"   Menaces analysées  : {len(resultat['menaces_analysees'])}")
    print(f"   Alertes envoyées   : {resultat['alertes_envoyees']}")
    print(f"\n   📊 Logs agents :")
    for msg in resultat["messages"]:
        print(f"   → {msg['agent']} | {msg['timestamp']} | {msg['statut']}")
    print(f"\n   🔍 Traces LangSmith :")
    print(f"   → https://smith.langchain.com")
    print("="*60)
