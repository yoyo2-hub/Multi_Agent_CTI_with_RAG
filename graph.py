"""
==========================================
 LANGGRAPH — Multi-Agent Orchestration
==========================================
Coordinates the complete pipeline via a state graph:

  START → cti_analysis → mitre_mapping → aggregation → dashboard → pdf_report → END

Each node is an agent or processing module.
LangGraph manages the data flow and shared state.
"""
import json
from typing import TypedDict
from langgraph.graph import StateGraph, START, END

from cti_analysis_agent import analyze_message
from mitre_agent import run_mitre_analysis
from master.aggregator import aggregate_reports
from master.prioritizer import prioritize_actions
from master.prioritizer import generate_executive_summary
from master.dashboard import generate_dashboard
from master.pdf_report import generate_pdf_report



# SHARED GRAPH STATE

class PipelineState(TypedDict):
    """Shared state between all graph nodes."""
    messages: list[str]              # Raw CTI input messages
    cti_results: list[dict]          # CTI Analysis Agent results
    mitre_reports: list[dict]        # MITRE Mapping Agent reports
    aggregated_report: dict          # Consolidated report
    prioritized_actions: list[dict]  # Actions ranked by priority
    executive_summary: dict          # Summary for stakeholders
    dashboard_path: str              # Dashboard PNG path
    pdf_path: str                    # Final PDF path


# GRAPH NODES

def cti_analysis_node(state: PipelineState) -> PipelineState:
    """
    Node 1: Runs the CTI Analysis Agent on each message.
    Extracts IOCs, behaviors, patterns, RAG context.
    """
    print("\n🔍 [NODE] CTI Analysis Agent")
    results = []
    for i, msg in enumerate(state["messages"]):
        print(f"  Analysing message {i+1}/{len(state['messages'])}...")
        result = analyze_message(msg)
        results.append(result)

    state["cti_results"] = results
    return state


def mitre_mapping_node(state: PipelineState) -> PipelineState:
    """
    Node 2: Runs the MITRE Mapping Agent on each CTI result.
    Maps → Scores → Mitigations → JSON Report.
    """
    print("\n🗺️  [NODE] MITRE Mapping Agent")
    reports = []
    for i, cti in enumerate(state["cti_results"]):
        print(f"  Mapping report {i+1}/{len(state['cti_results'])}...")
        # ✅ Pass the full cti dict directly (not cti.get("output"))
        report = run_mitre_analysis(cti)
        reports.append(report)

    state["mitre_reports"] = reports
    return state


def aggregation_node(state: PipelineState) -> PipelineState:
    """
    Node 3: Aggregates all reports into a consolidated report.
    Computes global statistics and prioritizes actions.
    """
    print("\n📊 [NODE] Aggregation & Prioritization")

    aggregated = aggregate_reports(state["mitre_reports"])
    state["aggregated_report"] = aggregated
    state["prioritized_actions"] = prioritize_actions(aggregated)
    state["executive_summary"] = generate_executive_summary(aggregated)

    return state


def dashboard_node(state: PipelineState) -> PipelineState:
    """Node 4: Generates the visual dashboard (PNG)."""
    print("\n📈 [NODE] Dashboard Generation")
    path = generate_dashboard(state["aggregated_report"])
    state["dashboard_path"] = path
    return state


def pdf_node(state: PipelineState) -> PipelineState:
    """Node 5: Generates the final PDF report."""
    print("\n📄 [NODE] PDF Report Generation")

    # ✅ Sanitize all strings in aggregated_report before PDF generation
    import json
    clean_report = json.loads(
        json.dumps(state["aggregated_report"])
        .replace("\u2014", "-")
        .replace("\u2013", "-")
        .replace("—", "-")
        .replace("–", "-")
    )
    clean_actions = json.loads(
        json.dumps(state["prioritized_actions"])
        .replace("\u2014", "-")
        .replace("\u2013", "-")
        .replace("—", "-")
        .replace("–", "-")
    )

    path = generate_pdf_report(
        aggregated_report=clean_report,
        prioritized_actions=clean_actions,
        executive_summary=state["executive_summary"],
        dashboard_path=state["dashboard_path"],
        output_path="cti_report.pdf",
    )
    state["pdf_path"] = path
    return state

# GRAPH CONSTRUCTION

def build_pipeline() -> StateGraph:
    """
    Builds the LangGraph state graph.

    Flow:
      START → cti_analysis → mitre_mapping → aggregation → dashboard → pdf_report → END
    """
    graph = StateGraph(PipelineState)

    # Add nodes
    graph.add_node("cti_analysis", cti_analysis_node)
    graph.add_node("mitre_mapping", mitre_mapping_node)
    graph.add_node("aggregation", aggregation_node)
    graph.add_node("dashboard", dashboard_node)
    graph.add_node("pdf_report", pdf_node) 

    # Define sequential flow
    graph.add_edge(START, "cti_analysis")
    graph.add_edge("cti_analysis", "mitre_mapping")
    graph.add_edge("mitre_mapping", "aggregation")
    graph.add_edge("aggregation", "dashboard")
    graph.add_edge("dashboard", "pdf_report")
    graph.add_edge("pdf_report", END)

    return graph.compile()


def run_pipeline(messages: list[str]) -> PipelineState:
    """
    Runs the complete pipeline.

    Args:
        messages: List of raw CTI messages to analyze.

    Returns:
        Final state containing all results.
    """
    pipeline = build_pipeline()

    initial_state: PipelineState = {
        "messages": messages,
        "cti_results": [],
        "mitre_reports": [],
        "aggregated_report": {},
        "prioritized_actions": [],
        "executive_summary": {},
        "dashboard_path": "",
        "pdf_path": "",
    }

    final_state = pipeline.invoke(initial_state)
    return final_state