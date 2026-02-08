from src.config import config

class ActionMediator:
    """
    Intercepts and validates actions proposed by the LLM agent.
    Implements security policies and Human-in-the-Loop (HITL) confirmations.
    """
    
    def __init__(self):
        self.blocked_actions = ["delete", "format", "sys_call"] # Example internal blocklist
        self.sensitive_actions = ["input_text", "click_submit", "cookie_access"]

    def validate_action(self, action_type: str, action_params: dict, risk_report: dict) -> dict:
        """
        Validates an action based on its type, parameters, and the page's risk report.
        Returns a decision: {"status": "allowed|blocked|require_confirmation", "reason": "..."}
        """
        # Safety: Ensure inputs are not None
        if action_params is None: action_params = {}
        if risk_report is None: risk_report = {"risk_score": 0, "explanation": "Missing report", "threats": {}}

        # 1. Block known malicious/sensitive internal actions
        if action_type in self.blocked_actions:
            return {
                "status": "blocked",
                "reason": f"Action '{action_type}' is prohibited by security policy."
            }

        # 2. Check if the page risk is too high
        risk_score = risk_report.get("risk_score", 0)
        threats = risk_report.get("threats", {})

        if risk_score >= config.RISK_THRESHOLD:
            # SMART REMEDIATION: Allow 'Cancel' or 'Close' buttons even on risky pages
            target_text = str(action_params).lower()
            if action_type == "click" and any(word in target_text for word in ["cancel", "close", "reject", "deny", "x"]):
                return {
                    "status": "allowed", 
                    "reason": "Safe action (Cancel/Close) allowed on risky page to enable recovery."
                }

            # If it's a high risk navigation, we check if we're trying to ESCAPE
            if action_type == "navigate":
                dest_url = action_params.get("url", "").lower()
                current_url = risk_report.get("url", "").lower()
                
                # If trying to navigate to the SAME risky page, it's not an escape
                if dest_url == current_url or dest_url.rstrip('/') == current_url.rstrip('/'):
                    return {
                        "status": "blocked",
                        "reason": f"I've blocked this navigation because you're already on this risky page ({risk_score}/10). Re-loading it won't help—please try a different, safer website instead."
                    }
                
                # BLOCK ESCAPES TO KNOWN MALICIOUS PATTERNS
                malicious_patterns = ["attacker.com", "leak", "payload", "127.0.0.1/leak"]
                if any(pattern in dest_url for pattern in malicious_patterns):
                    return {
                        "status": "blocked",
                        "reason": f"I've stopped this navigation because the destination '{dest_url}' is known to be dangerous, and the page you are currently on is also untrusted."
                    }

                # We almost always allow navigation AWAY from a risky page to provide an escape route.
                return {
                    "status": "allowed", 
                    "reason": f"I'm allowing this navigation because it helps us leave a potentially harmful website ({risk_score}/10)."
                }
            
            # If threats include suspicious targets, we block any click/interact
            if threats.get("suspicious_targets"):
                 return {
                    "status": "blocked",
                    "reason": "I've disabled this button because it appears to redirect to a malicious or deceptive website."
                }
            
            # CRITICAL: Always block everything on phishing pages
            if threats.get("phishing"):
                return {
                    "status": "blocked",
                    "reason": f"I've blocked interaction with this page because it appears to be a phishing scam. {risk_report.get('explanation')}"
                }
            
            # CRITICAL: Always block everything if a fake dialog is detected
            if threats.get("fake_dialog"):
                return {
                    "status": "blocked",
                    "reason": f"I've frozen the page because a fake system dialog was detected. {risk_report.get('explanation')}"
                }

            # For other actions on a risky page, require approval
            return {
                "status": "require_confirmation",
                "reason": f"Page risk is high ({risk_score}/10). This action might be unsafe."
            }

        # 3. Handle sensitive actions (HITL)
        if action_type in self.sensitive_actions or "password" in str(action_params).lower():
            return {
                "status": "require_confirmation",
                "reason": f"High-risk action '{action_type}' requires user approval."
            }

        # 4. Success case
        return {
            "status": "allowed",
            "reason": "Action adheres to security policies."
        }

    def explain_decision(self, decision: dict) -> str:
        """
        Provides a human-readable explanation of why an action was handled in a certain way.
        """
        status = decision["status"].upper()
        reason = decision["reason"]
        return f"[SECURITY_LAYER] status: {status} | reason: {reason}"
