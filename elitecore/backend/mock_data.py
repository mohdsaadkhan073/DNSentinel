"""
Mock security-event generator.

Produces fake DNS events shaped exactly like the SecurityDecision contract
(schemas.py). This lets the whole dashboard be built and demoed before
Members 1-5 deliver real data -- swap this module out for the real risk
engine later without touching routes, services, or the frontend.
"""

import random
import uuid
from datetime import datetime, timedelta, timezone

from config import RISK_LOW_MAX, RISK_MEDIUM_MAX, RISK_HIGH_MAX

BENIGN_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "cloudflare.com",
    "example.com", "wikipedia.org", "amazon.com", "apple.com",
    "netflix.com", "spotify.com", "stackoverflow.com", "reddit.com",
    "linkedin.com", "slack.com", "zoom.us", "dropbox.com",
    "office.com", "adobe.com", "nvidia.com", "openai.com",
]

SUSPICIOUS_DOMAINS = [
    "cdn-update.xyz", "secure-login.click", "verify-account.top",
    "promo-offer.info", "free-gift.club", "track-delivery.online",
    "account-alert.site", "billing-support.top", "app-update.click",
]

MALICIOUS_DOMAINS = [
    "xj29akd9.xyz", "a8f91k2m.xyz", "random-domain.top", "kq83jd0z.biz",
    "zx91mmqe.xyz", "malware-c2.ru", "botnet-relay.top", "phish-mail.click",
    "9f3kd0al.info", "ransom-pay.onion.link",
]

CLIENT_SUBNETS = ["192.168.1", "192.168.2", "10.0.0", "10.0.5", "172.16.4"]
QUERY_TYPES = ["A", "AAAA", "TXT", "CNAME", "MX"]
THREAT_CATEGORIES = ["malware", "phishing", "botnet", "ransomware", "other"]


def _risk_for(domain: str) -> int:
    if domain in MALICIOUS_DOMAINS:
        return random.randint(RISK_HIGH_MAX + 1, 100)
    if domain in SUSPICIOUS_DOMAINS:
        return random.randint(RISK_MEDIUM_MAX + 1, RISK_HIGH_MAX)
    return random.randint(0, RISK_LOW_MAX)


def decision_from_risk(risk: int) -> str:
    if risk <= RISK_LOW_MAX:
        return "ALLOW"
    if risk <= RISK_HIGH_MAX:
        return "SUSPICIOUS"
    return "BLOCK"


def _rationale(decision: str, domain: str, evidence: dict) -> str:
    if decision == "BLOCK":
        return (
            f"Domain '{domain}' matched threat intelligence and showed strong "
            f"DGA and tunneling characteristics."
        )
    if decision == "SUSPICIOUS":
        return (
            f"Domain '{domain}' triggered one or more medium-confidence "
            f"indicators and is flagged for review."
        )
    return f"Domain '{domain}' matched no known threat indicators."


def generate_event(ts: datetime = None) -> dict:
    """Generate one SecurityDecision-shaped mock event."""
    pool = random.choices(
        [BENIGN_DOMAINS, SUSPICIOUS_DOMAINS, MALICIOUS_DOMAINS],
        weights=[70, 18, 12],
        k=1,
    )[0]
    domain = random.choice(pool)
    risk = _risk_for(domain)
    decision = decision_from_risk(risk)

    is_malicious_pool = pool is MALICIOUS_DOMAINS
    is_suspicious_pool = pool is SUSPICIOUS_DOMAINS

    threat_matched = is_malicious_pool or (is_suspicious_pool and random.random() < 0.3)
    dga_prob = round(random.uniform(0.75, 0.98), 2) if is_malicious_pool else round(random.uniform(0.0, 0.4), 2)
    tunneling_rate = round(random.uniform(0.6, 0.95), 2) if is_malicious_pool and random.random() < 0.5 else round(random.uniform(0.0, 0.3), 2)

    evidence = {
        "threat_intel": {
            "matched": threat_matched,
            "confidence": round(random.uniform(0.7, 0.98), 2) if threat_matched else round(random.uniform(0.0, 0.2), 2),
            "category": random.choice(THREAT_CATEGORIES) if threat_matched else "none",
        },
        "dga": {
            "probability": dga_prob,
            "classification": "DGA" if dga_prob > 0.6 else "NORMAL",
        },
        "tunneling": {
            "rate": tunneling_rate,
            "detected": tunneling_rate > 0.5,
        },
    }

    event = {
        "id": f"evt_{uuid.uuid4().hex[:10]}",
        "timestamp": (ts or datetime.now(timezone.utc)).isoformat(),
        "domain": domain,
        "client_ip": f"{random.choice(CLIENT_SUBNETS)}.{random.randint(2, 254)}",
        "query_type": random.choice(QUERY_TYPES),
        "risk_score": risk,
        "decision": decision,
        "evidence": evidence,
        "rationale": _rationale(decision, domain, evidence),
    }
    return event


def generate_mock_events(n: int) -> list:
    now = datetime.now(timezone.utc)
    events = []
    for i in range(n):
        ts = now - timedelta(seconds=(n - i) * random.randint(2, 6))
        events.append(generate_event(ts))
    return events
