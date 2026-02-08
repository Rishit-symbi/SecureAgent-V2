import time
import asyncio
from src.security_engine import SecurityEngine

async def benchmark():
    engine = SecurityEngine()
    
    # Sample complex HTML
    html = "<html><body>" + "<div>Test Content</div>" * 1000 + "</body></html>"
    
    start = time.perf_counter()
    report = engine.analyze_page(html, "http://example.com")
    end = time.perf_counter()
    
    print(f"Performance Results:")
    print(f"Time taken: {(end - start) * 1000:.2f}ms")
    print(f"Risk Score: {report['risk_score']}")

if __name__ == "__main__":
    asyncio.run(benchmark())
