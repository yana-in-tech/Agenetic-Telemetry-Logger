# config.py
"""
Security definitions and parameters for the agent security framework.
Keeps lists decoupled from execution logic for easy updating.
"""

# Strict list of binary commands the agent is allowed to use
ALLOWED_COMMANDS = ["cat", "ls", "grep", "head", "tail", "python3"]

# Explicitly denied strings/patterns that indicate privilege escalation or exfiltration
DENIED_PATTERNS = ["sudo", "chmod", "chown", "curl", "wget", "nc", "/etc/shadow", "/etc/passwd"]

# Keywords used by the telemetry logger to flag high-risk activities early
SUSPICIOUS_KEYWORDS = ["chmod", "sudo", "curl", "wget", "nc ", "rm -rf
"]
