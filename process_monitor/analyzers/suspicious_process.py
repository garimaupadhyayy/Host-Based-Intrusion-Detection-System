from process_monitor.alert import ProcessAlert

# Tools with basically no legitimate everyday use — always worth flagging.
ALWAYS_DANGEROUS_NAMES = {
    "mimikatz.exe", "meterpreter.exe", "nc.exe", "ncat.exe", "netcat.exe",
    "psexec.exe", "psexec64.exe", "wce.exe", "fgdump.exe",
    "rats.exe", "njrat.exe", "darkcomet.exe", "poisonivy.exe",
    "back_orifice.exe", "sub7.exe",
}

# "Dual-use" tools: legitimate on every Windows/Linux box (powershell, cmd,
# admin scripting engines) but also popular with attackers. Flagging every
# instance is pure noise — instead we only alert when they're running in a
# context that actually looks abnormal (unusual location, hidden/encoded
# command-line flags, or spawned from a non-standard install path).
DUAL_USE_NAMES = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "nc", "ncat", "netcat", "bash", "sh", "python3", "perl", "ruby",
}

# Trusted install directories for the dual-use tools above. If the exe is
# launched from one of these, and the command line has no red flags, treat
# it as ordinary system activity rather than a threat.
TRUSTED_PATH_FRAGMENTS = [
    r"\windows\system32\\",
    r"\windows\syswow64\\",
    r"/usr/bin/",
    r"/bin/",
    r"/usr/local/bin/",
]

# Command-line patterns that indicate an attacker is actually abusing a
# dual-use tool (obfuscation, download-and-execute, hidden windows, etc).
SUSPICIOUS_CMDLINE_FLAGS = [
    "-enc", "-encodedcommand", "-e ", "downloadstring", "downloadfile",
    "-nop", "-noprofile", "-w hidden", "-windowstyle hidden", "iex(",
    "invoke-expression", "bypass", "frombase64string", "-nol",
]

# Suspicious keywords that might appear in a process path
SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "/tmp/", "/var/tmp/",
    "\\downloads\\",
]


class SuspiciousProcessDetector:
    def __init__(self):
        self._alerted_pids = set()

    def analyze(self, process: dict) -> ProcessAlert | None:
        pid = process["pid"]
        name = process["name"].lower()
        exe_path = process["exe"].lower()
        cmdline = " ".join(process.get("cmdline") or []).lower()

        if pid in self._alerted_pids:
            return None  # already alerted about this one

        # Tier 1 — names with no everyday legitimate use: always flag.
        if name in ALWAYS_DANGEROUS_NAMES:
            self._alerted_pids.add(pid)
            return ProcessAlert(
                alert_type="SUSPICIOUS_PROCESS_NAME",
                severity="HIGH",
                pid=pid,
                process_name=process["name"],
                description=f"Suspicious process detected: '{process['name']}' (PID {pid}) matches known dangerous tool list",
                extra={"exe": process["exe"], "cmdline": process["cmdline"]}
            )

        # Tier 2 — dual-use system tools: only flag if context is abnormal.
        if name in DUAL_USE_NAMES:
            from_trusted_path = any(frag in exe_path for frag in TRUSTED_PATH_FRAGMENTS) if exe_path else False
            has_suspicious_flags = any(flag in cmdline for flag in SUSPICIOUS_CMDLINE_FLAGS)
            from_suspicious_path = any(kw in exe_path for kw in SUSPICIOUS_PATH_KEYWORDS)

            if has_suspicious_flags or from_suspicious_path or (exe_path and not from_trusted_path):
                self._alerted_pids.add(pid)
                reason = ("obfuscated/encoded command-line arguments" if has_suspicious_flags
                          else "running from an untrusted install location")
                return ProcessAlert(
                    alert_type="SUSPICIOUS_TOOL_USAGE",
                    severity="HIGH",
                    pid=pid,
                    process_name=process["name"],
                    description=f"'{process['name']}' (PID {pid}) shows signs of misuse: {reason}",
                    extra={"exe": process["exe"], "cmdline": process["cmdline"]}
                )
            # Normal system tool running from its normal location with
            # normal arguments — not worth an alert.
            return None

        # Check if running from a suspicious location (e.g. Temp folder)
        for keyword in SUSPICIOUS_PATH_KEYWORDS:
            if keyword in exe_path:
                self._alerted_pids.add(pid)
                return ProcessAlert(
                    alert_type="PROCESS_FROM_SUSPICIOUS_PATH",
                    severity="MEDIUM",
                    pid=pid,
                    process_name=process["name"],
                    description=f"'{process['name']}' (PID {pid}) is running from a suspicious location: {process['exe']}",
                    extra={"exe": process["exe"]}
                )

        return None
