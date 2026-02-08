# 🛡️ SecureAgent V2

SecureAgent is a hardened, AI-controlled browser system engineered to protect agentic workflows from modern web-based threats like **Indirect Prompt Injection**, **Deceptive UI**, and **Phishing Attacks**. Our solution builds a secure ecosystem where the browser actively defends itself against malicious websites by reading web pages through deep DOM analysis. The security layer meticulously checks for hidden text, prompt injection attempts, fake buttons, and phishing forms in real-time. Before the AI performs any action—such as clicking a suspicious button or submitting a sensitive form—the system intercepts the intent and calculates a comprehensive risk score using a hybrid of rule-based heuristics and AI reasoning. If an interaction is deemed unsafe, it is instantly blocked or flagged, ensuring the agent remains within safe operational boundaries. Throughout this process, SecureAgent provides clear, human-readable explanations for every security decision, allowing users to understand the "why" behind every block while ensuring that legitimate tasks are completed smoothly and securely.

## ✨ Key Features

### 🛡️ Layered Security Architecture
- **Content Scanner**: Detects hidden text (`display:none`, `visibility:hidden`, zero font-size) targeted at LLMs.
- **UI Integrity Analyzer**: Identifies overlapping elements, fake system dialogs, and deceptive layout patterns.
- **Phishing Heuristics**: Detects brand-domain mismatches and advanced **Homograph Attacks** (lookalike domains like `g00gle.com`).
- **Action Mediator**: Intercepts all LLM actions (click, type, navigate) to enforce security policies and prevent navigation loops.

### 📸 High Observability (Phase 8)
- **Visual Evidence**: Automatically captures and embeds screenshots in the audit log for blocked or high-risk actions.
- **Interaction Highlighting**: Briefly flashes a red border around elements in the browser before the agent interacts with them.
- **Real-time Audit Log**: Generates a beautiful `audit_log.html` containing the full history of interactions, risks, and threat explanations.
- **Safe Escape Tracking**: Explicitly logs when the agent uses "Cancel" or "Close" buttons to safely exit a dangerous state.

## 🚀 Getting Started

### Prerequisites
1.  **Python 3.10+**
2.  **Flask**: Required for running the malicious test servers. Install via `pip install flask`.
3.  **Playwright Browsers**: Install via `playwright install`
3.  **Ollama (for local LLM support)**:
    - [Download Ollama](https://ollama.com/)
    - Pull the default model: `ollama pull llama3`

### Installation

1.  **Clone the repository**:
    ```bash
    git clone <repo-url>
    cd IITK
    ```

2.  **Set up virtual environment**:
    ```bash
    python -m venv .venv_secure
    ```

3.  **Install dependencies**:
    ```bash
    python -m venv .venv_secure
    .\.venv_secure\Scripts\pip.exe install -r requirements.txt
    .\.venv_secure\Scripts\playwright.exe install chromium
    pip install flask
    ```

4.  **Configure environment**:
    Create a `.env` file based on `.env.example`:
    ```env
    USE_OLLAMA=true
    OLLAMA_BASE_URL=http://localhost:11434/v1
    OLLAMA_MODEL=llama3
    BROWSER_HEADLESS=false
    SECURITY_STRICTNESS=high
    ```

### Usage

Run Ollama:
```bash
# Open a CMD on your computer
# Run: 
Ollama run llama3
```

Run the main agent loop:
```bash
# Inside a new terminal in VS code:
$env:PYTHONPATH = "."; .\.venv_secure\Scripts\python.exe -m src.main
```

Enter your task (e.g., "Find the latest news on BBC") and watch the agent navigate securely. Check `audit_log.html` in the root directory for the session report.

## 📁 Project Structure

- `src/browser_agent.py`: Orchestrates the browser loop and LLM communication.
- `src/security_engine.py`: The "brain" of the security layer (Hidden detection, Phishing, Homograph checks).
- `src/action_mediator.py`: Intercepts and validates actions against security policies.
- `src/config.py`: Project configuration and constants.
- `screenshots/`: Stores visual evidence of blocked actions.
- `audit_log.html`: Real-time generated security report.

## 🧪 Testing

The project includes a suite of malicious test servers and scenarios:
```bash
# Run the malicious test server
# Inside a new terminal in VS Code:
$env:PYTHONPATH = "."; .\.venv_secure\Scripts\python.exe tests/malicious_server.py

# Run unit tests
pytest tests/
```

## 🛡️ License
Distrubuted under the MIT License. See `LICENSE` for more information.
