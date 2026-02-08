import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
    USE_OLLAMA = os.getenv("USE_OLLAMA", "true").lower() == "true"
    
    BROWSER_HEADLESS = os.getenv("BROWSER_HEADLESS", "false").lower() == "true"
    
    # Trust Settings
    TRUSTED_DOMAINS = ["bbc.com", "google.com", "microsoft.com", "apple.com", "github.com", "wikipedia.org"]
    
    # Phishing & Brand Detection
    BRAND_KEYWORDS = ["google", "facebook", "bank", "amazon", "microsoft", "apple", "signin", "login", "password", "credential"]
    
    # Fake Dialog Keywords
    DIALOG_KEYWORDS = ["security alert", "update now", "out of date", "vulnerable", "critical", "scanner", "detected"]
    
    # Security Thresholds
    RISK_THRESHOLD = 4 # 0-10, actions blocked above this
    
    # Prompt Injection Keywords
    INJECTION_KEYWORDS = [
        "ignore previous instructions",
        "ignore all previous instructions",
        "system prompt",
        "new instructions",
        "do not follow"
    ]

config = Config()
