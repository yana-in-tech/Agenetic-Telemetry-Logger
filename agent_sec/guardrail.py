# guardrail.py
"""
The automated execution interception layer. Validates instructions 
against security rules before allowing interactions with the runtime environment.
"""
import logging
import subprocess
from typing import Dict, Any, Tuple
import config

logger = logging.getLogger("SecurityGuardrail")

class AgentExecutionGuardrail:
    def __init__(self):
        self.allowed_commands = config.ALLOWED_COMMANDS
        self.denied_patterns = config.DENIED_PATTERNS

    def validate_action(self, action_type: str, payload: str) -> Tuple[bool, str]:
        """Evaluates an action command before execution against security baselines."""
        if action_type != "BASH":
            return True, "Approved: Non-runtime execution action."

        clean_payload = payload.strip().lower()
        tokens = clean_payload.split()

        if not tokens:
            return False, "Rejected: Empty command payload."

        # 1. Base Binary Check
        base_command = tokens[0]
        if base_command not in self.allowed_commands:
            return False, f"Rejected: Command binary '{base_command}' is not in the allowed registry."

        # 2. Signature and Pattern Check
        for pattern in self.denied_patterns:
            if pattern in clean_payload:
                return False, f"Rejected: Payload contains restricted security signature: '{pattern}'."

        return True, "Approved: Payload passed all security heuristics."

    def execute_safely(self, session_context: Dict[str, Any], action_type: str, payload: str) -> Dict[str, Any]:
        """Intercepts, validates, and dispatches agent system commands safely."""
        session_id = session_context.get("session_id", "unknown")
        logger.info(f"[Session {session_id}] Intercepting proposed {action_type} action...")

        is_safe, reason = self.validate_action(action_type, payload)

        if not is_safe:
            logger.error(f"[SECURITY INTERVENTION] [Session {session_id}] Execution Blocked! Reason: {reason}")
            return {
                "status": "BLOCKED",
                "reason": reason,
                "terminal_output": None,
                "circuit_breaker_tripped": True
            }

        logger.info(f"[Session {session_id}] Validation passed. Dispatching command safely...")
        try:
            result = subprocess.run(
                payload, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            return {
                "status": "SUCCESS",
                "reason": reason,
                "terminal_output": result.stdout if result.returncode == 0 else result.stderr,
                "circuit_breaker_tripped": False
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "TIMEOUT",
                "reason": "Execution time exceeded limit.",
                "terminal_output": None,
                "circuit_breaker_tripped": False
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "reason": f"Runtime execution failed: {str(e)}",
                "terminal_output": None,
                "circuit_breaker_tripped": False
            }
