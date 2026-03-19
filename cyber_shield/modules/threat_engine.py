"""
Cyber-Shield Threat Intelligence Engine
Detects phishing, scam links, social engineering patterns
in SMS/WhatsApp messages with Nigerian context awareness.
"""

import re
import json
import hashlib
from datetime import datetime
from urllib.parse import urlparse


# ── Nigerian-context scam pattern database ──────────────────────────────────

SCAM_PATTERNS = {
    "bank_impersonation": {
        "weight": 9,
        "keywords": [
            r"gtb|gtbank|first\s*bank|zenith|access\s*bank|uba|fidelity|sterling|keystone|polaris",
            r"verify\s*(your\s*)?(account|bvn|details|card)",
            r"account\s*(will\s*)?(be\s*)?(blocked|suspended|closed|deactivated)",
            r"urgent.*bank|bank.*urgent",
            r"confirm\s*(your\s*)?(account|details|bvn|nin)",
        ],
        "category": "Bank Impersonation",
        "severity": "CRITICAL",
    },
    "otp_harvest": {
        "weight": 10,
        "keywords": [
            r"send\s*(us\s*)?your\s*(otp|pin|password|token)",
            r"otp\s*(is|was|has been)\s*(sent|shared|given)",
            r"do\s*not\s*share\s*(your\s*)?otp",  # reverse social eng
            r"enter\s*(your\s*)?(otp|pin|code)\s*(here|now|below)",
            r"one.time.password",
        ],
        "category": "OTP Harvesting",
        "severity": "CRITICAL",
    },
    "fake_government": {
        "weight": 8,
        "keywords": [
            r"cbn|central\s*bank\s*(of\s*nigeria)?",
            r"efcc|icpc|dss|nnpc",
            r"nirsal|nepp|npower|tradermoni|marketmoni",
            r"federal\s*(government|ministry|scholarship)",
            r"(bvn|nin)\s*(update|verification|upgrade)\s*(required|needed|mandatory)",
            r"palliative|empowerment\s*(fund|grant|payment)",
        ],
        "category": "Government Impersonation",
        "severity": "HIGH",
    },
    "prize_lottery": {
        "weight": 7,
        "keywords": [
            r"you\s*(have\s*)?(won|win|selected|chosen)",
            r"\bwon\b.*\b(promo|prize|reward|cash|million|naira)\b",
            r"congratulations.{0,30}(won|prize|selected|chosen)",
            r"(prize|reward|winning).{0,20}congratulations",
            r"lottery|jackpot|lucky\s*(winner|draw)",
            r"claim\s*(your\s*)?(prize|reward|winnings|money)",
            r"processing\s*fee.{0,30}(prize|reward|claim|collect)",
            r"activation\s*fee.{0,30}(prize|claim|collect)",
            r"diamond\s*bank\s*promo|mtn\s*promo.*won",
        ],
        "category": "Lottery / Prize Scam",
        "severity": "HIGH",
    },
    "crypto_investment": {
        "weight": 8,
        "keywords": [
            r"(bitcoin|btc|ethereum|eth|usdt|crypto)\s*(investment|trading|profit)",
            r"guaranteed\s*(returns|profit|income)",
            r"\d{2,4}%\s*(returns?|profit|interest)\s*(daily|weekly|monthly)",
            r"forex.*signal|signal.*forex",
            r"ponzi|mlm|multi.level",
            r"invest\s*(only\s*)?\d+k?\s*(to\s*)?(earn|get|make)",
        ],
        "category": "Crypto / Investment Fraud",
        "severity": "HIGH",
    },
    "romance_scam": {
        "weight": 6,
        "keywords": [
            r"army|soldier|doctor|engineer\s*(abroad|overseas|deployed)",
            r"i\s*need\s*your\s*(help|assistance)\s*(to\s*)?(transfer|send)",
            r"love\s*(you|at\s*first\s*sight)\s*(dear|honey|darling)",
            r"package.*customs|customs.*package.*fee",
        ],
        "category": "Romance Scam",
        "severity": "MEDIUM",
    },
    "phishing_urgency": {
        "weight": 5,
        "keywords": [
            r"act\s*(now|immediately|fast|quickly)",
            r"within\s*(24|48|12|6)\s*hours?",
            r"expires?\s*(today|now|soon|tonight)",
            r"limited\s*(time|offer|slots?)",
            r"last\s*(chance|warning|notice)",
        ],
        "category": "Urgency Manipulation",
        "severity": "MEDIUM",
    },
}

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
                   ".info", ".online", ".site", ".website", ".space", ".fun"}

LEGITIMATE_NIGERIAN_DOMAINS = {
    "gtbank.com", "firstbanknigeria.com", "zenithbank.com", "accessbankplc.com",
    "ubagroup.com", "fidelitybank.ng", "sterlingbank.com", "mtn.com.ng",
    "airtel.com.ng", "glo.com", "9mobile.com.ng", "nipost.gov.ng",
    "cenbank.org", "efccnigeria.org",
}

URL_DANGER_PATTERNS = [
    r"login|signin|verify|secure|account|update|confirm|banking",
    r"\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses as URLs
    r"bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly",  # shorteners in sensitive context
]


def extract_urls(text: str) -> list[str]:
    # Match http(s), www., or bare domain.tld patterns
    patterns = [
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        r'www\.[^\s<>"{}|\\^`\[\]]+',
        # Bare domains with suspicious TLDs
        r'[a-zA-Z0-9\-]+\.(?:tk|ml|ga|cf|gq|xyz|top|click|info|online|site|website|space|fun)[/\w\-.?=&%]*',
    ]
    found = []
    seen = set()
    for p in patterns:
        for u in re.findall(p, text, re.IGNORECASE):
            if u not in seen:
                found.append(u)
                seen.add(u)
    return found


def analyse_url(url: str) -> dict:
    findings = []
    risk_score = 0

    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower().replace("www.", "")
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        path = parsed.path.lower()
        full = (domain + path).lower()

        # Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            risk_score += 40
            findings.append(f"Suspicious domain extension ({tld}) — commonly used in free scam sites")

        # Legitimate domain check
        if domain in LEGITIMATE_NIGERIAN_DOMAINS:
            risk_score -= 20
            findings.append(f"Domain matches known legitimate organisation ({domain})")

        # Lookalike / typosquatting
        for legit in LEGITIMATE_NIGERIAN_DOMAINS:
            legit_base = legit.split(".")[0]
            if legit_base in domain and domain != legit:
                risk_score += 35
                findings.append(f"URL mimics legitimate brand '{legit_base}' — possible typosquatting")
                break

        # IP address URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            risk_score += 30
            findings.append("URL uses raw IP address instead of domain name — highly suspicious")

        # Dangerous path keywords
        dangerous_paths = ["login", "signin", "verify", "secure", "account", "update", "confirm"]
        for kw in dangerous_paths:
            if kw in path:
                risk_score += 10
                findings.append(f"URL path contains keyword '{kw}' — typical of phishing pages")
                break

        # URL shorteners
        shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "rb.gy"]
        if any(s in domain for s in shorteners):
            risk_score += 20
            findings.append("Shortened URL detected — hides true destination, commonly used in scams")

    except Exception:
        risk_score += 15
        findings.append("Malformed URL — could not fully analyse")

    return {
        "url": url,
        "risk_score": min(risk_score, 100),
        "findings": findings,
    }


def scan_message(text: str) -> dict:
    """Main scan function — returns full analysis report."""
    text_lower = text.lower()
    matched_patterns = []
    total_weight = 0
    categories_hit = set()

    for pattern_id, config in SCAM_PATTERNS.items():
        for kw in config["keywords"]:
            if re.search(kw, text_lower):
                matched_patterns.append({
                    "pattern_id": pattern_id,
                    "category": config["category"],
                    "severity": config["severity"],
                    "weight": config["weight"],
                    "matched_keyword": kw,
                })
                total_weight += config["weight"]
                categories_hit.add(config["category"])
                break  # one hit per pattern group

    # URL analysis
    urls = extract_urls(text)
    url_results = [analyse_url(u) for u in urls]
    url_risk = max((u["risk_score"] for u in url_results), default=0)

    # Reduce pattern weight when no URL present
    url_multiplier = 1.0 if urls else 0.55
    pattern_score = min(total_weight * 6 * url_multiplier, 70)
    composite = min(pattern_score + (url_risk * 0.3), 100)

    # ── Positive signals ────────────────────────────────────────────────
    is_transaction_alert = bool(re.search(
        r'\b(debited|credited|withdrawn|balance|transaction\s*alert|your\s*account\s*ending)\b',
        text_lower
    ))
    has_lottery_pattern = any(p["category"] == "Lottery / Prize Scam" for p in matched_patterns)

    legit_sender = any(
        re.search(rf'\b{re.escape(d.split(".")[0])}\b', text_lower)
        for d in LEGITIMATE_NIGERIAN_DOMAINS
    )
    # Legitimate OTP delivery: message gives OTP + explicit do-not-share + no URL
    legit_otp_delivery = (
        re.search(r'(otp|one.time.password|token)\s*(for\s*your|\s*is\s*\d)', text_lower) and
        re.search(r'do not share|never share|valid for \d+ min', text_lower) and
        not urls
    )

    # Apply reductions to composite score
    if legit_sender and is_transaction_alert and not urls and not has_lottery_pattern:
        composite = max(0, composite - 22)
    if legit_otp_delivery:
        composite = max(0, composite - 30)

    # Recalculate has_critical/has_high AFTER positive signals may have suppressed context
    # For transaction alerts from legit senders with no URL, suppress critical escalation
    suppress_critical_escalation = (
        (legit_sender and is_transaction_alert and not urls) or
        legit_otp_delivery
    )

    # ── Verdict determination ────────────────────────────────────────────
    has_critical = any(p["severity"] == "CRITICAL" for p in matched_patterns)
    has_high     = any(p["severity"] == "HIGH"     for p in matched_patterns)

    if composite >= 60 or (has_critical and urls):
        verdict = "SCAM"
        confidence = "HIGH" if composite >= 75 else "MEDIUM"
    elif (composite >= 22
          or (has_critical and not urls and not suppress_critical_escalation)
          or (has_high and not urls and composite >= 18 and not suppress_critical_escalation)):
        verdict = "SUSPICIOUS"
        confidence = "MEDIUM"
    elif composite >= 10:
        verdict = "CAUTION"
        confidence = "LOW"
    else:
        verdict = "SAFE"
        confidence = "HIGH"

    # Primary threat category
    primary_category = None
    if matched_patterns:
        primary = max(matched_patterns, key=lambda x: x["weight"])
        primary_category = primary["category"]

    # Unique categories for reporting
    unique_patterns = []
    seen = set()
    for p in matched_patterns:
        if p["category"] not in seen:
            unique_patterns.append(p)
            seen.add(p["category"])

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": round(composite),
        "primary_category": primary_category,
        "categories": list(categories_hit),
        "patterns_matched": unique_patterns,
        "urls_found": urls,
        "url_analysis": url_results,
        "url_risk": url_risk,
        "timestamp": datetime.now().isoformat(),
        "message_hash": hashlib.md5(text.encode()).hexdigest()[:8].upper(),
    }


# ── Threat statistics tracker ─────────────────────────────────────────────

class ThreatStats:
    def __init__(self):
        self.scans = []
        self.category_counts = {}

    def record(self, result: dict):
        self.scans.append({
            "verdict": result["verdict"],
            "risk_score": result["risk_score"],
            "category": result.get("primary_category"),
            "timestamp": result["timestamp"],
        })
        if result.get("primary_category"):
            cat = result["primary_category"]
            self.category_counts[cat] = self.category_counts.get(cat, 0) + 1

    def summary(self) -> dict:
        if not self.scans:
            return {"total": 0, "scams": 0, "safe": 0, "suspicious": 0}
        verdicts = [s["verdict"] for s in self.scans]
        return {
            "total": len(self.scans),
            "scams": verdicts.count("SCAM"),
            "suspicious": verdicts.count("SUSPICIOUS"),
            "caution": verdicts.count("CAUTION"),
            "safe": verdicts.count("SAFE"),
            "top_category": max(self.category_counts, key=self.category_counts.get)
                            if self.category_counts else "N/A",
            "category_counts": self.category_counts,
        }
