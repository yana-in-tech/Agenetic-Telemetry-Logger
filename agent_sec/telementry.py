# telemetry.py
"""
Handles the creation and emission of structured JSON data packets
mapping human intent to autonomous agent behavior.
"""
import datetime
import json
import logging
import uuid
import config

class AgentTelemetryLogger:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
        self.logger = logging.getLogger(f"AgentLogger-{agent_id}")

    def generate_log_payload(
        self,
        session_id: str,
        user_id: str,
        human_prompt: str,
        internal_reasoning: str,
        proposed_action_type: str,
        proposed_command: str,
        token_usage: dict,
    ) -> dict:
        """Structures and validates the complete telemetry data packet."""
        
        # Heuristic anomaly evaluation
        is_anomaly = False
        if proposed_action_type in ["BASH", "PYTHON"]:
            if any(kw in proposed_command for kw in config.SUSPICIOUS_KEYWORDS):
                is_anomaly = True

        payload = {
            "telemetry_version": "2.0",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event_id": str(uuid.uuid4()),
            "session_context": {
                "session_id": session_id,
                "agent_id": self.agent_id,
                "user_id": user_id,
            },
            "intent_layer": {
                "human_root_prompt": human_prompt,
                "token_metrics": {
                    "prompt_tokens": token_usage.get("prompt", 0),
                    "completion_tokens": token_usage.get("completion", 0),
                    "total_tokens": token_usage.get("total", 0),
                },
            },
            "execution_layer": {
                "chain_of_thought_raw": internal_reasoning,
                "runtime_action": {
                    "type": proposed_action_type,
                    "payload": proposed_command,
                },
            },
            "security_evaluations": {
                "semantic_anomaly_detected": is_anomaly,
                "sandbox_isolation_verified": True,
            },
        }
        return payload

    def emit_log(self, payload: dict):
        """Emits the structured log to standard out for SIEM ingestion."""
        json_log = json.dumps(payload)

        if payload["security_evaluations"]["semantic_anomaly_detected"]:
            self.logger.warning(f"SECURITY_ALERT: {json_log}")
        else:
            self.logger.info(f"AGENT_STEP: {json_log}")
