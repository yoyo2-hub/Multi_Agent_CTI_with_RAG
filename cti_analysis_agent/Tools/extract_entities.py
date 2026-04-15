'''TOOL 1 — Entity Extraction (HYBRID)
Extract IOC : IPs, URLs, hashes, wallets, emails, known malware'''

import re
from typing import Any
from langchain_core.tools import tool
from llm_helper import llm_analyze

# =========================
# LAYER 1 : STATIC EXTRACTION (Regex + Seeds)
# =========================

IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s<>\"'\)]{3,}")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|ru|io|xyz|top|cc|"
    r"tk|ml|ga|cf|info|biz|onion|gov|edu|co|me)\b"
)

BTC_PATTERN = re.compile(r"\b(?:1|3)[A-HJ-NP-Za-km-z1-9]{25,39}\b|bc1[a-zA-HJ-NP-Z0-9]{25,87}\b")
ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR_PATTERN = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# =========================
# THREAT INTEL SEEDS
# =========================

THREAT_INTEL_SEEDS = {
    "malware_families": {
        "emotet", "trickbot", "qakbot", "icedid",
        "redline", "vidar", "raccoon stealer", "lumma stealer",
        "formbook", "stealc", "meta stealer",
        "remcos", "asyncrat", "njrat", "agent tesla",
        "smokeloader", "squirrelwaffle", "icebot"
    },

    "ransomware_groups": {
        "lockbit", "alphv", "blackcat",
        "conti", "revil", "darkside",
        "ryuk", "hive", "blackbasta",
        "play", "clop", "royal",
        "medusa", "akira", "dharma",
        "rhysida", "noescape"
    },

    "apt_groups": {
        "apt28", "fancy bear", "apt29", "cozy bear",
        "sandworm", "turla",
        "lazarus", "bluenoroff", "apt38",
        "apt1", "apt10", "apt41",
        "fin7", "ta505"
    },

    "abused_tools": {
        "cobalt strike", "mimikatz",
        "metasploit", "empire", "bloodhound",
        "psexec", "rclone",
        "anydesk", "teamviewer", "ngrok",
        "powershell empire"
    }
}

# =========================
# HELPERS
# =========================

def _deduplicate(items: list) -> list:
    seen = set()
    out = []
    for i in items:
        n = i.strip().lower()
        if n not in seen:
            seen.add(n)
            out.append(i.strip())
    return out

def _find_seeds(seeds: set, text: str) -> list:
    """Helper to find seeds using word boundaries to prevent false positives"""
    found = []
    for seed in seeds:
        # Use regex word boundaries (\b) to avoid matching 'play' in 'player' 
        # or common words outside of a specific entity context
        if re.search(rf"\b{re.escape(seed)}\b", text):
            found.append(seed)
    return found

# =========================
# LAYER 1: STATIC EXTRACTION
# =========================

def _static_extraction(text: str) -> dict:
    sha256 = _deduplicate(SHA256_PATTERN.findall(text))
    sha1 = _deduplicate([h for h in SHA1_PATTERN.findall(text) if h not in sha256])
    md5 = _deduplicate([h for h in MD5_PATTERN.findall(text) if h not in sha256 + sha1])

    urls = _deduplicate(URL_PATTERN.findall(text))
    domains = _deduplicate(DOMAIN_PATTERN.findall(text))
    domains = [d for d in domains if not any(d in u for u in urls)]

    text_lower = text.lower()

    return {
        "ips": _deduplicate(IP_PATTERN.findall(text)),
        "urls": urls,
        "domains": domains,

        "crypto_wallets": {
            "btc": _deduplicate(BTC_PATTERN.findall(text)),
            "eth": _deduplicate(ETH_PATTERN.findall(text)),
            "xmr": _deduplicate(XMR_PATTERN.findall(text)),
        },

        "hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256
        },

        # Swapped to word-boundary helper function
        "malware_names": _deduplicate(_find_seeds(THREAT_INTEL_SEEDS["malware_families"], text_lower)),
        "ransomware_groups": _deduplicate(_find_seeds(THREAT_INTEL_SEEDS["ransomware_groups"], text_lower)),
        "apt_groups": _deduplicate(_find_seeds(THREAT_INTEL_SEEDS["apt_groups"], text_lower)),
        "tools_abused_static": _deduplicate(_find_seeds(THREAT_INTEL_SEEDS["abused_tools"], text_lower)),

        "emails": _deduplicate(EMAIL_PATTERN.findall(text)),
        "cves": _deduplicate(CVE_PATTERN.findall(text)),
    }

# =========================
# LAYER 2: LLM EXTRACTION
# =========================

LLM_EXTRACTION_PROMPT = """
You are a Cyber Threat Intelligence IOC extraction expert.

Your task: Extract ALL indicators of compromise and threat-related entities
from the provided message that REGEX ALONE might miss.

Focus especially on:
- NEW or UNKNOWN malware names (variants, codenames, aliases)
- Threat actor names / APT groups (even informal nicknames)
- Obfuscated IOCs (defanged IPs like "192.168.1[.]1", hXXp://, etc.)
- Campaign names or operation codenames
- Targeted sectors, countries, or organizations
- Tools and frameworks mentioned (even legitimate ones used maliciously)
- Any CVE identifiers
- Cryptocurrency wallet addresses (any format)

Return ONLY valid JSON. Ensure all lists contain ONLY STRINGS (do not output dictionaries or objects).
Use exactly this format:
{
    "new_malware": ["name1", "name2"],
    "threat_actors": ["actor1", "actor2"],
    "defanged_iocs": ["10.0.0[.]1", "hXXps://example[.]com"],
    "campaign_names": ["campaign1"],
    "targeted_sectors": ["sector1"],
    "targeted_countries": ["country1"],
    "tools_abused": ["tool1"],
    "additional_cves": ["CVE-XXXX-XXXX"],
    "context_notes": "Brief note about anything unusual spotted"
}

If a category has no findings, use an empty list [].
Be precise. Do not hallucinate — only extract what is actually in the text.
"""

def _llm_extraction(text: str) -> dict:
    result = llm_analyze(LLM_EXTRACTION_PROMPT, text)

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

# =========================
# MERGE LAYERS
# =========================

def _merge_results(static: dict, llm: dict) -> dict:

    TOOL_BLACKLIST = {"powershell", "cmd", "mshta", "wscript", "rundll32", "vssadmin"}

    malware = _deduplicate(static["malware_names"] + llm.get("new_malware", []))
    ransomware = _deduplicate(static["ransomware_groups"])
    apt = _deduplicate(static["apt_groups"])

    tools = [
        t for t in _deduplicate(
            static["tools_abused_static"] + llm.get("tools_abused", [])
        )
        if t.lower() not in TOOL_BLACKLIST
    ]

    defanged = llm.get("defanged_iocs", [])
    extra_ips, extra_urls = [], []

    for ioc in defanged:
        # --- DEFENSIVE PROGRAMMING BLOCK ---
        # 1. If Qwen stubbornly returns a dictionary like {"ip": "1.1.1.1", "type": "defanged"}
        if isinstance(ioc, dict):
            # Extract all the values from the dictionary into a list
            items_to_process = [str(val) for val in ioc.values()]
        # 2. If the LLM actually listens to the prompt and returns a string
        elif isinstance(ioc, str):
            items_to_process = [ioc]
        # 3. If it returns something completely bizarre, skip it
        else:
            continue

        for item in items_to_process:
            # Skip random metadata tags like "type": "defanged" 
            if not isinstance(item, str):
                continue
                
            clean_ioc = (
                item.replace("[.]", ".")
                   .replace("hxxps://", "https://")
                   .replace("hXXps://", "https://")
                   .replace("hxxp://", "http://")
                   .replace("hXXp://", "http://")
            )

            # Use IP_PATTERN.search instead of re.match for better reliability
            if IP_PATTERN.search(clean_ioc):
                extra_ips.append(clean_ioc)
            elif clean_ioc.startswith("http"):
                extra_urls.append(clean_ioc)
            
    cves = _deduplicate(static["cves"] + llm.get("additional_cves", []))

    merged = {
        "ips": _deduplicate(static["ips"] + extra_ips),
        "urls": _deduplicate(static["urls"] + extra_urls),
        "domains": static["domains"],

        "crypto_wallets": static["crypto_wallets"],
        "hashes": static["hashes"],

        "malware_names": malware,
        "ransomware_groups": ransomware,
        "apt_groups": apt,
        "tools_abused": tools,

        "emails": static["emails"],
        "cves": cves,

        "threat_actors": _deduplicate(llm.get("threat_actors", [])),
        "campaign_names": _deduplicate(llm.get("campaign_names", [])),
        "targeted_sectors": llm.get("targeted_sectors", []),
        "targeted_countries": llm.get("targeted_countries", []),
        "context_notes": llm.get("context_notes", ""),

        "ioc_count": 0
    }

    merged["ioc_count"] = (
        len(merged["ips"]) +
        len(merged["urls"]) +
        len(merged["domains"]) +
        len(merged["emails"]) +
        len(merged["malware_names"]) +
        len(merged["cves"]) +
        sum(len(v) for v in merged["crypto_wallets"].values()) +
        sum(len(v) for v in merged["hashes"].values())
    )

    return merged

# =========================
# LANGCHAIN TOOL
# =========================

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
    static = _static_extraction(message)
    llm = _llm_extraction(message)
    return _merge_results(static, llm)