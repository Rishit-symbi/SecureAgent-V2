import asyncio
import sys
from src.browser_agent import BrowserAgent
from src.config import config

async def main():
    if not config.OPENAI_API_KEY and not config.USE_OLLAMA:
        print("[!] Error: No API credentials found. Set OPENAI_API_KEY or use OLLAMA.")
        sys.exit(1)

    agent = BrowserAgent()
    await agent.start()
    
    try:
        print("\n=== SecureAgentBrowser Prototype ===")
        print(f"[*] Engine: {'Ollama' if config.USE_OLLAMA else 'OpenAI'}")
        print(f"[*] Model: {agent.model}")
        print("Type 'exit' to quit.")
        
        while True:
            # Use run_in_executor to avoid blocking the event loop while waiting for input
            try:
                loop = asyncio.get_event_loop()
                task = await loop.run_in_executor(None, lambda: input("\nEnter your task (e.g., 'Find the latest news on BBC'): "))
                
                if not task or task.lower() == 'exit':
                    break
                
                await agent.execute_task(task)
            except (KeyboardInterrupt, EOFError):
                break
            except Exception as e:
                print(f"[!] Error in task: {e}")
                
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[*] Shutting down...")
    finally:
        await agent.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except RuntimeError as e:
        if "Event loop is closed" not in str(e):
            raise
