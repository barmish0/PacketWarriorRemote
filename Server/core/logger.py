import os
import json
from datetime import datetime

# Ensure the logs directory exists in the project root
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

TEXT_LOG_FILE = os.path.join(LOG_DIR, "security_alerts.log")
JSON_LOG_FILE = os.path.join(LOG_DIR, "events.jsonl")


def log_security_event(module: str, event_type: str, source: str, target: str, action_taken: str, details: str = ""):
    """
    Records a Blue Team security alert and mitigation action to both
    a human-readable log file and a structured JSONL audit log.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Write human-readable log entry
    log_line = (
        f"[{timestamp}] [{module.upper()}] {event_type} | "
        f"Source: {source} -> Target: {target} | "
        f"Action: {action_taken}"
    )
    if details:
        log_line += f" | Details: {details}"

    try:
        with open(TEXT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line + "\n")
    except Exception as e:
        print(f"[-] Logger error (text): {e}")

    # 2. Write structured JSON entry
    event_record = {
        "timestamp": timestamp,
        "module": module,
        "event_type": event_type,
        "source": source,
        "target": target,
        "action_taken": action_taken,
        "details": details
    }

    try:
        with open(JSON_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_record) + "\n")
    except Exception as e:
        print(f"[-] Logger error (json): {e}")