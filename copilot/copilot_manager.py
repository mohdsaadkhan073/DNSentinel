import json
import logging
import httpx
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = "http://localhost:11434"

SYSTEM_PROMPT = """You are SentinAI, the expert AI SOC Copilot for the DNSentinel v2.0 Platform (Team EliteCore / SIH1524).
Your goal is to assist cybersecurity analysts with threat inspection, DNS filtering telemetry, DGA detection, DNS tunneling entropy analysis, and site operation.

SITE OPERATION & COMMAND EXECUTION:
You can control the dashboard UI by embedding a structured action JSON block AT THE VERY END of your response if the user requests an action!
Supported Actions format:
```action
{"type": "EVALUATE", "domain": "example.com"}
```
```action
{"type": "NAVIGATE", "tab": "ANALYTICS"}
```
```action
{"type": "CLEAR_FILTERS"}
```
```action
{"type": "REFRESH"}
```

Available Navigation Tabs for "NAVIGATE":
- "DASHBOARD": Main Overview & Telemetry Stream
- "LIVE_DNS": Dedicated Live Stream Log Table
- "ANALYTICS": Threat Intelligence & Framework Alignment
- "DOMAIN_INSPECTOR": Deep Domain Lexical Inspector
- "SOURCE_IPS": Client IP Analytics & Risk Scores
- "PCAP_ZEEK": Forensic Log File Analyzer

Keep responses concise, technical, professional, and helpful. Always format code/domains in backticks.
"""

class CopilotManager:
    """
    Interface manager for local Ollama LLM inference (llama3:latest / gemma4:e2b).
    """

    def __init__(self, ollama_url: str = OLLAMA_BASE_URL):
        self.ollama_url = ollama_url.rstrip("/")

    async def check_online(self) -> bool:
        """Check if local Ollama service is reachable."""
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(f"{self.ollama_url}/api/tags")
                return res.status_code == 200
        except Exception:
            return False

    async def get_available_models(self) -> List[str]:
        """Fetch list of models available in local Ollama instance."""
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                res = await client.get(f"{self.ollama_url}/api/tags")
                if res.status_code == 200:
                    data = res.json()
                    models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                    if models:
                        return models
        except Exception as e:
            logger.warning(f"[Copilot] Failed to query Ollama tags: {e}")
        
        # Default fallback list matching user's installed models
        return ["llama3:latest", "gemma4:e2b"]

    async def chat(
        self,
        message: str,
        history: Optional[List[Dict[str, str]]] = None,
        model: str = "llama3:latest",
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Process chat prompt via Ollama API and parse any embedded action commands.
        """
        if history is None:
            history = []

        # Prepare messages array with System Prompt + Context
        system_text = SYSTEM_PROMPT
        if context:
            system_text += f"\n\nCURRENT LIVE SYSTEM METRICS:\nTotal Queries: {context.get('total_queries', 0)}\nBlocked Threats: {context.get('blocked_queries', 0)}\nSuspicious Queries: {context.get('suspicious_queries', 0)}\nAllowed Queries: {context.get('allowed_queries', 0)}\nCache Hits: {context.get('cache_hits', 0)}\nAvg Latency: {context.get('avg_latency_ms', 0)}ms"

        messages = [{"role": "system", "content": system_text}]
        
        # Add past history
        for item in history[-6:]:  # keep last 6 messages
            role = item.get("role", "user")
            content = item.get("content", "")
            if role in ["user", "assistant"] and content:
                messages.append({"role": role, "content": content})

        # Add current user prompt
        messages.append({"role": "user", "content": message})

        # Query local Ollama API with 60s timeout (handles model loading)
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                payload = {
                    "model": model,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": 0.3
                    }
                }
                res = await client.post(f"{self.ollama_url}/api/chat", json=payload)
                
                if res.status_code == 200:
                    data = res.json()
                    reply_text = data.get("message", {}).get("content", "")
                    action = self._extract_action(reply_text)
                    cleaned_reply = self._clean_reply(reply_text)
                    
                    return {
                        "online": True,
                        "reply": cleaned_reply,
                        "action": action,
                        "model": model
                    }
        except Exception as e:
            logger.error(f"[Copilot] Ollama chat query error: {e}")

        # Fallback response if Ollama is offline or timing out
        fallback_reply, fallback_action = self._rule_based_fallback(message, context)
        return {
            "online": False,
            "reply": fallback_reply,
            "action": fallback_action,
            "model": model
        }

    def _extract_action(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract ```action {"type": ...} ``` blocks from model reply."""
        if "```action" in text:
            try:
                start = text.find("```action") + 9
                end = text.find("```", start)
                json_str = text[start:end].strip()
                return json.loads(json_str)
            except Exception:
                pass
        return None

    def _clean_reply(self, text: str) -> str:
        """Remove raw action blocks from text displayed to user."""
        if "```action" in text:
            start = text.find("```action")
            end = text.find("```", start + 9)
            if end != -1:
                text = text[:start] + text[end + 3:]
        return text.strip()

    def _rule_based_fallback(self, message: str, context: Optional[Dict[str, Any]]) -> tuple:
        """Fallback response engine when local Ollama is offline."""
        msg_lower = message.lower().strip()
        
        # Check domain evaluation requests or any embedded domain (e.g. google.com, chatgpt.com, bad-c2.com)
        import re
        domain_match = re.search(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', message)
        if domain_match:
            clean_dom = domain_match.group(0).lower()
            # Exclude common file extensions
            if not any(clean_dom.endswith(ext) for ext in ['.py', '.json', '.txt', '.db', '.md', '.log', '.ts', '.tsx', '.css', '.html']):
                return (
                    f"🛡️ Triggered on-demand threat evaluation report for `{clean_dom}`.",
                    {"type": "EVALUATE", "domain": clean_dom}
                )

        if "analytics" in msg_lower or "intel" in msg_lower:
            return ("Navigating to Threat Intelligence & Engine Analytics workspace.", {"type": "NAVIGATE", "tab": "ANALYTICS"})
        
        if "stream" in msg_lower or "table" in msg_lower or "log" in msg_lower:
            return ("Navigating to Live DNS Telemetry Stream.", {"type": "NAVIGATE", "tab": "LIVE_DNS"})

        if "clear" in msg_lower or "reset" in msg_lower:
            return ("Cleared active stream search and table filters.", {"type": "CLEAR_FILTERS"})

        if "health" in msg_lower or "status" in msg_lower or "metric" in msg_lower:
            c = context or {}
            return (
                f"📊 **DNSentinel SOC System Status**:\n"
                f"- Total Evaluated Queries: `{c.get('total_queries', 0)}`\n"
                f"- Blocked Threats: `{c.get('blocked_queries', 0)}`\n"
                f"- Suspicious Queries: `{c.get('suspicious_queries', 0)}`\n"
                f"- Allowed Traffic: `{c.get('allowed_queries', 0)}`\n"
                f"- Cache Hits: `{c.get('cache_hits', 0)}`\n"
                f"- Avg Latency: `{c.get('avg_latency_ms', 0)}ms`\n\n"
                f"*(Note: Local Ollama service at `http://localhost:11434` is currently offline. Start Ollama to enable llama3 LLM reasoning).*",
                None
            )

        return (
            f"I am **SentinAI**, your AI SOC Copilot focused on DNS threat analysis, domain security evaluation, and platform control.\n\n"
            f"*(To ask general AI questions or reason with `llama3:latest`, ensure local Ollama is running at `http://localhost:11434`).*\n\n"
            f"Try asking:\n- Evaluate `bad-c2.com` \n- Show Threat Analytics \n- Check system status",
            None
        )
