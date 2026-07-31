import re
from datetime import datetime

# Pattern for common log formats like:
# 2026-05-11 12:00:01 ERROR Something bad happened
# [2026-05-11 12:00:01] WARNING Disk almost full
COMMON_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})'
    r'.*?(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL|SEVERE)'
    r'.*?(?P<message>.+)',
    re.IGNORECASE
)

# Windows Event Log style: "Nov 11 12:00:01 hostname keyword: message"
SYSLOG_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})'
    r'\s+\S+\s+(?P<message>.+)'
)

def parse_line(raw_line: str, log_file: str) -> dict:
    """
    Parses a single log line into a clean dictionary.
    Always returns something useful even if parsing fails.
    """
    result = {
        "raw": raw_line,
        "log_file": log_file,
        "timestamp": datetime.now(),
        "level": "UNKNOWN",
        "message": raw_line,   # fallback: treat whole line as message
    }

    # Try common format first
    match = COMMON_PATTERN.search(raw_line)
    if match:
        try:
            result["timestamp"] = datetime.strptime(
                match.group("timestamp").replace("T", " "),
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            pass
        result["level"] = match.group("level").upper()
        result["message"] = match.group("message").strip()
        return result

    # Try syslog format
    match = SYSLOG_PATTERN.search(raw_line)
    if match:
        result["message"] = match.group("message").strip()
        return result

    return result  # return as-is if no pattern matched