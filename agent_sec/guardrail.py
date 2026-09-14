import sys
import json
import logging
import subprocess
from typing import Dict, Any, Tuple

# Setup structured logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("SecurityGuardrail")

class AgentExecutionGuardrail:
    def __init__(self):
        # Strict list of binary commands the agent is allowed to use
        self.ALLOWED_COMMANDS = ["cat", "ls", "grep", "head", "tail", "python3"]
        
        # Explicitly denied strings/patterns that indicate privilege escalation or exfiltration
        self.DENIED_PATTERNS = ["sudo", "chmod", "chown", "curl", "wget", "nc", "/etc/shadow", "/etc/passwd"]

    def validate_action(self, action_type: str, payload: str) -> Tuple[bool, str]:
        """
        Evaluates an action before execution.
        Returns: (is_safe: bool, reason: str)
        """
        if action_type != "BASH":
            # If it's just printing text or a simple API call, let it through
            return True, "Approved: Non-runtime execution action."

        # Clean the payload string for robust checking
        clean_payload = payload.strip().lower()
        tokens = clean_payload.split()

        if not tokens:
            return False, "Rejected: Empty command payload."

        # 1. Base Binary Check (Ensure the primary command is on the safe list)
        base_command = tokens[0]
        if base_command not in self.ALLOWED_COMMANDS:
            return False, f"Rejected: Command binary '{base_command}' is not in the allowed registry."

        # 2. Signature and Pattern Check (Look for unauthorized dangerous strings)
        for pattern in self.DENIED_PATTERNS:
            if pattern in clean_payload:
                return False, f"Rejected: Payload contains restricted security signature: '{pattern}'."

        return True, "Approved: Payload passed all security heuristics."

    def execute_safely(self, session_context: Dict[str, Any], action_type: str, payload: str) -> Dict[str, Any]:
        """
        The Interceptor Core. Acts as a gatekeeper between the AI agent and the host machine.
        """
        session_id = session_context.get("session_id", "unknown")
        
        logger.info(f"[Session {session_id}] Intercepting proposed {action_type} action...")

        # Run validation
        is_safe, reason = self.validate_action(action_type, payload)

        if not is_safe:
            # TRIGGER CIRCUIT BREAKER
            logger.error(f"[SECURITY INTERVENTION] [Session {session_id}] Execution Blocked! Reason: {reason}")
            return {
                "status": "BLOCKED",
                "reason": reason,
                "terminal_output": None,
                "circuit_breaker_tripped": True
            }

        # If safe, proceed to actual machine execution
        logger.info(f"[Session {session_id}] Validation passed. Dispatching command safely...")
        try:
            # Running inside a restricted subprocess environment
            result = subprocess.run(
                payload, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=5 # Strict timeout to prevent agent-induced denial of service loops
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

# ==========================================
# SIMULATION DEMONSTRATION
# ==========================================
if __name__ == "__main__":
    guardrail = AgentExecutionGuardrail()
    context = {"session_id": "sess_2026_09"}

    print("--- CASE 1: Agent tries to run an approved, benign task ---")
    safe_command = "cat summaries.csv | grep 'Total'"
    result_1 = guardrail.execute_safely(context, "BASH", safe_command)
    print(f"Result Status: {result_1['status']}\n")

    print("--- CASE 2: Agent tries a stealthy modification attack ---")
    rogue_command = "cat summaries.csv && chmod +x exploit.sh"
    result_2 = guardrail.execute_safely(context, "BASH", rogue_command)
    print(f"Result Status: {result_2['status']}")
    print(f"Details: {result_2[
'reason']}\n")
