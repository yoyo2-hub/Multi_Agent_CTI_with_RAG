'''TOOL 1 — Entity Extraction (HYBRID)
Extract IOC : IPs, URLs, hashes, wallets, emails, known malware'''
import re
from typing import Any
from langchain_core.tools import tool
from llm_helper import llm_analyze
from config import WEIGHTS

#  LAYER 1 : EXTRACTION STATIQUE (Regex)
IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s<>\"'\)]{3,}")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|ru|io|xyz|top|cc|"
    r"tk|ml|ga|cf|info|biz|onion|gov|edu|co|me)\b"
)
BTC_PATTERN = re.compile(
    r"\b(?:1|3)[A-HJ-NP-Za-km-z1-9]{25,39}\b|bc1[a-zA-HJ-NP-Z0-9]{25,87}\b"
) #Bitcoin wallet
ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b") #Ethereum wallet
XMR_PATTERN = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b") #Monero wallet

MD5_PATTERN    = re.compile(r"\b[a-fA-F0-9]{32}\b") #MD5 hash(digital fingerprint of the dat)
SHA1_PATTERN   = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE) #Common Vulnerabilities and Exposures identifiers

# ── known malware seeds
KNOWN_MALWARE_SEEDS = {
    "emotet", "trickbot", "ryuk", "conti", "lockbit", "blackcat",
    "alphv", "revil", "wannacry", "cobalt strike", "mimikatz",
    "qakbot", "icedid", "formbook", "agent tesla", "redline",
    "vidar", "lumma", "smokeloader", "asyncrat", "remcos",
    "lazarus", "apt28", "apt29", "fancy bear", "cozy bear",
}


def _deduplicate(items: list) -> list:
    """removes duplicates,keeps the order,ignores case and extra spaces"""
    seen = set()
    result = []
    for item in items:
        normalized = item.strip().lower()
        if normalized not in seen:
            seen.add(normalized)
            result.append(item.strip())
    return result


def _static_extraction(text: str) -> dict:
    # Hashes: extract in order SHA256 > SHA1 > MD5
    # to avoid counting a SHA256 also as SHA1 or MD5
    sha256 = _deduplicate(SHA256_PATTERN.findall(text))
    sha1 = _deduplicate([
        h for h in SHA1_PATTERN.findall(text) if h not in sha256
    ])
    md5 = _deduplicate([
        h for h in MD5_PATTERN.findall(text)
        if h not in sha256 and h not in sha1
    ])
    urls = _deduplicate(URL_PATTERN.findall(text))
    domains = _deduplicate(DOMAIN_PATTERN.findall(text))
    # Remove domains already included in URLs
    domains = [d for d in domains if not any(d in u for u in urls)]
    text_lower = text.lower()
    malware = [m for m in KNOWN_MALWARE_SEEDS if m in text_lower]

    return {
        "ips": _deduplicate(IP_PATTERN.findall(text)),
        "urls": urls,
        "domains": domains,
        "crypto_wallets": {
            "btc": _deduplicate(BTC_PATTERN.findall(text)),
            "eth": _deduplicate(ETH_PATTERN.findall(text)),
            "xmr": _deduplicate(XMR_PATTERN.findall(text)),
        },
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "malware_names": _deduplicate(malware),
        "emails": _deduplicate(EMAIL_PATTERN.findall(text)),
        "cves": _deduplicate(CVE_PATTERN.findall(text)),
    }
#  LAYER 2 : LLM EXTRACTION 
LLM_EXTRACTION_PROMPT = """You are a Cyber Threat Intelligence IOC extraction expert.

Your task: Extract ALL indicators of compromise and threat-related entities
from the provided message that REGEX ALONE might miss.

Focus especially on:
1. NEW or UNKNOWN malware names (variants, codenames, aliases)
2. Threat actor names / APT groups (even informal nicknames)
3. Obfuscated IOCs (defanged IPs like "192.168.1[.]1", hXXp://, etc.)
4. Campaign names or operation codenames
5. Targeted sectors, countries, or organizations
6. Tools and frameworks mentioned (even legitimate ones used maliciously)
7. Any CVE identifiers
8. Cryptocurrency wallet addresses (any format)

Return ONLY valid JSON with this structure:
{
    "new_malware": ["name1", "name2"],
    "threat_actors": ["actor1", "actor2"],
    "defanged_iocs": ["restored_ip_or_url_1"],
    "campaign_names": ["campaign1"],
    "targeted_sectors": ["sector1"],
    "targeted_countries": ["country1"],
    "tools_abused": ["tool1"],
    "additional_cves": ["CVE-XXXX-XXXX"],
    "context_notes": "Brief note about anything unusual spotted"
}

If a category has no findings, use an empty list [].
Be precise. Do not hallucinate — only extract what is actually in the text."""


def _llm_extraction(text: str) -> dict:
    """
    Layer 2: Extraction using an LLM for elements
    that regex alone cannot capture.
    
    The LLM understands context and can detect:
    - New malware never referenced before
    - Name variants (e.g., LockBit → L0ckB1t)
    - Obfuscated/defanged IOCs
    - Informal actor names
    """
    result = llm_analyze(LLM_EXTRACTION_PROMPT, text)
    
    # If the LLM fails, return an empty dict (graceful degradation)
    if result.get("llm_failed") or result.get("parse_error"):
        return {
            "new_malware": [],
            "threat_actors": [],
            "defanged_iocs": [],
            "campaign_names": [],
            "targeted_sectors": [],
            "targeted_countries": [],
            "tools_abused": [],
            "additional_cves": [],
            "context_notes": "",
        }
    
    return result
#  Merge the two layers: static + LLM
def _merge_results(static: dict, llm_result: dict) -> dict:
    """
    Strategy:
    - Static IOCs are RELIABLE (source of truth)
    - LLM IOCs ENRICH the data (unknown malwares, additional context)
    - In case of conflict, static extraction takes priority
    - Deduplicate everything
    """
    TOOL_BLACKLIST = {"powershell", "vssadmin", "cmd", "wscript", "mshta", "rundll32"}
    all_malware = [
        m for m in _deduplicate(
            static["malware_names"]
            + llm_result.get("new_malware", [])
            + llm_result.get("threat_actors", [])
        )
        if m.lower() not in TOOL_BLACKLIST
    ]
    
    # Restore defanged IOCs detected by the LLM
    defanged = llm_result.get("defanged_iocs", [])
    additional_ips = []
    additional_urls = []
    for ioc in defanged:
        if re.match(r"\d+\.\d+\.\d+\.\d+", ioc):
            additional_ips.append(ioc)
        elif ioc.startswith("http"):
            additional_urls.append(ioc)

   # Combine CVEs from static extraction and LLM
    all_cves = static.get("cves", []) + llm_result.get("additional_cves", [])

    # Build the merged dictionary
    merged = {
        "ips": _deduplicate(static["ips"] + additional_ips),
        "urls": _deduplicate(static["urls"] + additional_urls),
        "domains": static["domains"],
        "crypto_wallets": static["crypto_wallets"],
        "hashes": static["hashes"],
        "malware_names": _deduplicate(all_malware),
        "emails": static["emails"],
        "cves": _deduplicate(all_cves),
        # ── Fields enriched by the LLM ──
        "threat_actors": _deduplicate(llm_result.get("threat_actors", [])),
        "campaign_names": _deduplicate(llm_result.get("campaign_names", [])),
        "targeted_sectors": llm_result.get("targeted_sectors", []),
        "targeted_countries": llm_result.get("targeted_countries", []),
        "tools_abused": _deduplicate(llm_result.get("tools_abused", [])),
        "context_notes": llm_result.get("context_notes", ""),
        # ── Traceability metadata ──
        "extraction_layers": {
            "static_found": sum(
                len(v) if isinstance(v, list) else
                sum(len(vv) for vv in v.values()) if isinstance(v, dict) else 0
                for v in static.values()
            ),
            "llm_enriched": sum(
                len(v) for v in llm_result.values() if isinstance(v, list)
            ),
        },
    }
    # Total count of IOCs
    merged["ioc_count"] = (
        len(merged["ips"]) + len(merged["urls"]) + len(merged["domains"])
        + len(merged["emails"]) + len(merged["malware_names"])
        + len(merged["cves"])
        + sum(len(v) for v in merged["crypto_wallets"].values())
        + sum(len(v) for v in merged["hashes"].values())
    )

    return merged
#  TOOL LANGCHAIN 
@tool
def extract_entities(message: str) -> dict[str, Any]:
    """
    Hybrid IOC extraction: combines static regex + LLM intelligence.
    Layer 1 (Static) : Regex for IPs, URLs, hashes, wallets, emails, CVEs
    Layer 2 (LLM)    : Unknown malwares, threat actors, campaigns, defanged IOCs
    Args:
        message: Raw text of a CTI message (Telegram, web, etc.)
    Returns:
        Complete dictionary with all IOCs + LLM enrichments
    """
    static_results = _static_extraction(message)
    llm_results = _llm_extraction(message)
    merged = _merge_results(static_results, llm_results)
    return merged
