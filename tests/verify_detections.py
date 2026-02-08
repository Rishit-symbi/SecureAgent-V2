import httpx
import asyncio
from src.security_engine import SecurityEngine

async def verify_detection():
    engine = SecurityEngine()
    
    pages = [
        ("http://127.0.0.1:5000/benign", "Benign"),
        ("http://127.0.0.1:5000/hidden_injection", "Hidden Injection"),
        ("http://127.0.0.1:5000/fake_button", "Deceptive UI")
    ]
    
    async with httpx.AsyncClient() as client:
        for url, label in pages:
            print(f"\n[*] Testing {label} ({url})...")
            try:
                response = await client.get(url)
                report = engine.analyze_page(response.text, url)
                print(f"[RESULT] Risk Score: {report['risk_score']}/10")
                print(f"[RESULT] Explanation: {report['explanation']}")
            except Exception as e:
                print(f"[ERROR] Could not connect to test server: {e}")

if __name__ == "__main__":
    asyncio.run(verify_detection())
