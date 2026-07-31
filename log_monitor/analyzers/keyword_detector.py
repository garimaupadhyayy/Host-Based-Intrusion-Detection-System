from log_monitor.alert import LogAlert

# Words that should NEVER appear in normal logs
# If they do, it is a serious red flag
CRITICAL_KEYWORDS = {
    "rootkit", "malware", "exploit", "payload", "shellcode",
    "reverse shell", "backdoor", "exfiltrat", "mimikatz",
    "meterpreter", "privilege escalat", "ransomware",
}

# Words that are suspicious but might be legitimate sometimes
WARNING_KEYWORDS = {
    "unauthorized", "intrusion", "attack", "breach",
    "violation", "suspicious", "anomaly", "hacked",
    "pentest", "vulnerability", "injection", "overflow",
    "port scan", "brute force",
}

class KeywordDetector:
    def __init__(self):
        self._alerted_lines: set[str] = set()

    def analyze(self, parsed: dict) -> LogAlert | None:
        message = parsed["message"].lower()
        raw = parsed["raw"]

        # Skip if we already alerted on this exact line
        if raw in self._alerted_lines:
            return None

        # Check critical keywords first
        for kw in CRITICAL_KEYWORDS:
            if kw in message:
                self._alerted_lines.add(raw)
                return LogAlert(
                    alert_type="DANGEROUS_KEYWORD",
                    severity="CRITICAL",
                    log_file=parsed["log_file"],
                    description=f"Critical keyword '{kw}' found in log — immediate investigation needed",
                    matched_line=raw,
                    extra={"keyword": kw, "category": "critical"}
                )

        # Check warning keywords
        for kw in WARNING_KEYWORDS:
            if kw in message:
                self._alerted_lines.add(raw)
                return LogAlert(
                    alert_type="SUSPICIOUS_KEYWORD",
                    severity="MEDIUM",
                    log_file=parsed["log_file"],
                    description=f"Suspicious keyword '{kw}' found in log",
                    matched_line=raw,
                    extra={"keyword": kw, "category": "warning"}
                )

        return None