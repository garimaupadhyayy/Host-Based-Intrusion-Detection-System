import re
from network_monitor.alert import NetworkAlert

SUSPICIOUS_TLDS = {".xyz", ".tk", ".pw", ".top", ".gq", ".cf", ".ml"}
MIN_SUSPICIOUS_LENGTH = 30
DGA_PATTERN = re.compile(r'[bcdfghjklmnpqrstvwxyz]{5,}', re.IGNORECASE)

class DNSAnalyzer:
    def analyze(self, parsed):
        dns = parsed.get("dns")
        if not dns:
            return None

        query = dns["query"].rstrip(".")
        reasons = []

        for tld in SUSPICIOUS_TLDS:
            if query.endswith(tld):
                reasons.append(f"suspicious TLD: {tld}")

        if len(query) > MIN_SUSPICIOUS_LENGTH:
            reasons.append(f"unusually long hostname ({len(query)} chars)")

        if DGA_PATTERN.search(query):
            reasons.append("DGA-like pattern detected")

        if reasons:
            return NetworkAlert(
                alert_type="SUSPICIOUS_DNS",
                severity="MEDIUM",
                src_ip=parsed["src_ip"],
                dst_ip=None,
                description=f"Suspicious DNS: '{query}' — {', '.join(reasons)}",
                extra={"query": query, "reasons": reasons}
            )
        return None