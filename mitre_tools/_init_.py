"""
Exporte les tools du MITRE Mapping Agent.
"""

from mitre.mitre_mapper import map_to_mitre
from mitre.severity_engine import calculate_severity
from mitre.mitigation_engine import recommend_mitigations
from mitre.report_generator import generate_report

MITRE_TOOLS = [
    map_to_mitre,
    calculate_severity,
    recommend_mitigations,
    generate_report,
]