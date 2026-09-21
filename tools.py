"""
Deterministic sensing/pre-check tools. These run as plain Python
functions — no model call needed — and their structured output is
what the LLM reasons over later, rather than asking the model to
search and interpret everything itself.
"""
import re
from datetime import datetime, timezone

def whois_domain_age(domain: str) -> dict:
    """Free, no API key required. Returns domain registration age in days."""
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return {"domain": domain, "age_days": None, "error": "no creation date found"}
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation).days
        return {"domain": domain, "age_days": age_days, "registrar": w.registrar}
    except Exception as e:
        return {"domain": domain, "age_days": None, "error": str(e)}


def web_search(query: str, max_results: int = 4) -> dict:
    """Free web search via DuckDuckGo — no API key required.
    This is the tool the agent's Act node calls when it decides
    it needs external evidence about a vendor."""
    try:
        #from duckduckgo_search import DDGS
        from ddgs import DDGS

        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
        return {
            "query": query,
            "results": [
                {"title": r.get("title", ""), "snippet": r.get("body", ""), "url": r.get("href", "")}
                for r in results
            ],
        }
    except Exception as e:
        return {"query": query, "results": [], "error": str(e)}


def extract_domain(vendor_or_url: str) -> str | None:
    """Best-effort: pull a bare domain out of a vendor name or URL for WHOIS lookup."""
    match = re.search(r"([a-z0-9-]+\.[a-z]{2,})", vendor_or_url.lower())
    return match.group(1) if match else None
