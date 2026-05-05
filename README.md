# 👻 SPECTER

> **Security Pentest Engine with Configurable Threat Exploration and Reporting**

An autonomous AI-powered web application pentester that works with **any LLM provider** — NVIDIA, OpenRouter, Ollama (free/local), OpenAI, or Anthropic. No Docker required.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Providers](https://img.shields.io/badge/providers-NVIDIA%20%7C%20OpenRouter%20%7C%20Ollama%20%7C%20OpenAI-green)](config.example.yaml)

---

## ✨ Features

- 🤖 **5 Specialist AI Agents** — Recon, Injection, XSS, Auth, SSRF
- 🔌 **Universal LLM Support** — plug in any OpenAI-compatible API
- 🆓 **Works with free tiers** — NVIDIA API, Ollama (local), OpenRouter
- 📊 **Rich Reports** — HTML, Markdown, and JSON output
- 💾 **Session persistence** — resume interrupted scans
- ⚡ **Parallel scanning** — run multiple agents simultaneously
- 🐍 **No Docker** — pure Python, runs anywhere
- 🧠 **Adaptive Agents** — self-modifying behavior based on scan results
- 📚 **Meta-Learning** — agents learn from previous scans
- 🤝 **Collaborative Planning** — agents coordinate attack strategies
- 📐 **Shannon Entropy Analysis** — information-theoretic anomaly detection

---

## 🚀 Quick Start

### 1. Clone
```bash
git clone https://github.com/nvnjswaroop/SPECTER.git
cd SPECTER
```

### 2. Install dependencies
```bash
# Windows
py -3.11 -m pip install -r requirements.txt

# Linux / Mac
pip3 install -r requirements.txt
```

### 3. Configure your LLM provider
```bash
cp config.example.yaml config.yaml
notepad config.yaml   # Windows
nano config.yaml      # Linux/Mac
```

Fill in your provider details. Examples:

**NVIDIA (free tier):**
```yaml
provider: nvidia
model: deepseek-ai/deepseek-r1
api_key: nvapi-xxxx
base_url: https://integrate.api.nvidia.com/v1
```

**Ollama (100% free, local):**
```yaml
provider: ollama
model: llama3
api_key: ollama
base_url: http://localhost:11434/v1
```

**OpenRouter:**
```yaml
provider: openrouter
model: anthropic/claude-sonnet-4-5
api_key: sk-or-xxxx
base_url: https://openrouter.ai/api/v1
```

### 4. Test your connection
```bash
py -3.11 specter.py --test-connection
```

### 5. Run a scan
```bash
# Full scan (all 5 agents)
py -3.11 specter.py -u https://your-target.com

# Specific agents only
py -3.11 specter.py -u https://your-target.com --agents recon xss

# Faster with parallel agents (careful with rate limits)
py -3.11 specter.py -u https://your-target.com --threads 3
```

---

## 🤖 Agents

| Agent | What it does |
|-------|-------------|
| `recon` | HTTP headers, port scan, tech fingerprinting, security header audit |
| `injection` | SQL injection, command injection, template injection (SSTI) |
| `xss` | Reflected XSS, stored XSS, DOM XSS pattern detection |
| `auth` | Default credentials, rate limiting, JWT flaws, insecure cookies |
| `ssrf` | SSRF, Local File Inclusion, path traversal, open redirects |
| `adaptive` | Adaptive recon with self-modifying behavior and context awareness |

---

## 🧠 Advanced Capabilities

### Self-Modifying Agents
Agents dynamically adjust their behavior based on scan results with context-aware decision making and performance metrics tracking.

### Meta-Learning Framework
Cross-target knowledge transfer, continuous learning from previous scans, and performance optimization through historical data analysis.

### Collaborative Multi-Agent Planning
Real-time coordination between multiple agents with a shared memory system for inter-agent communication and attack sequence optimization.

### Adaptive Payload Generation
AI-driven payload creation based on target analysis with self-generating bypass methods for WAFs and filters.

### Automated Exploit Development
Self-generating exploits from vulnerability patterns with automated exploit chaining and intelligent proof-of-concept generation.

### Predictive Vulnerability Scanning
AI prediction of likely vulnerabilities based on tech stack, historical correlation analysis, and probability scoring for vulnerability types.

### Intelligent Fuzzing
Smart fuzzing that learns from response patterns using neural network-based payload mutation and genetic algorithm payload evolution.

### Shannon Entropy Enhancement
- **Relative Entropy Analysis**: Kullback-Leibler Divergence for baseline comparison
- **Structural Entropy**: HTML tag and SQL keyword distribution analysis
- **Enhanced Genetic Fuzzing**: Multi-metric fitness functions for payload evolution
- **Baseline Persistence**: Session-based baseline storage for persistent comparison

---

## 🧪 Local Testing

### Option 1: Python HTTP Server
```bash
# Start a local test server
python -m http.server 5500

# Run a basic scan against it
python specter.py -u http://127.0.0.1:5500/test_page.html --agents recon xss
```

### Option 2: Node.js
```bash
npm install -g http-server
http-server -p 5500

python specter.py -u http://127.0.0.1:5500/test_page.html --agents adaptive recon xss injection
```

### Advanced Multi-Agent Local Scan
```bash
python specter.py -u http://127.0.0.1:5500/test_page.html --agents adaptive recon injection xss auth ssrf --threads 3
```

### Run Tests
```bash
python -m pytest -q
```

Tests cover entropy utilities, adaptive agent orchestration, and basic LLM routing.

---

## 📄 Reports

Reports are auto-generated after every scan in `reports/`:

| Format | Description |
|--------|-------------|
| `*_report.html` | Beautiful dark-themed HTML report |
| `*_report.md` | Markdown report (great for GitHub issues) |
| `*_report.json` | Raw JSON for automation/integration |

---

## 📁 Project Structure

```
SPECTER/
├── specter.py              # Main CLI entry point
├── config.yaml             # Your config (gitignored)
├── config.example.yaml     # Safe template to share
├── requirements.txt
├── core/
│   ├── llm_router.py       # Universal LLM adapter
│   ├── agent_base.py       # Base agent class
│   ├── session.py          # Session persistence
│   ├── exploit_engine.py   # AI-powered exploit generation
│   ├── adversarial_sim.py  # Adversarial testing simulation
│   ├── intelligent_fuzzer.py
│   ├── bypass_engine.py    # Automated bypass techniques
│   ├── behavioral_analysis.py
│   ├── predictive_scanner.py
│   ├── collaboration.py
│   ├── self_optimizer.py
│   ├── meta_learning.py
│   └── context_aware.py
├── agents/
│   ├── recon.py
│   ├── injection.py
│   ├── xss.py
│   ├── auth.py
│   ├── ssrf.py
│   └── advanced_attacks.py
├── tools/
│   └── http_client.py      # Shared HTTP utilities
└── reports/
    └── reporter.py         # HTML/MD/JSON report generator
```

---

## ⚙️ Configuration

```yaml
provider: <nvidia|ollama|openrouter|openai|anthropic>
model: <model-id>
api_key: <your-key>       # never commit this file – it is git-ignored
base_url: <optional-override-URL>
max_tokens: 4096
temperature: 0.2
request_timeout: 30
threads: 3
max_rounds: 10
```

**Environment variable overrides:**
- `SPECTER_API_KEY`
- `SPECTER_BASE_URL`
- `SPECTER_MODEL`

---

## 🏗️ Architecture Overview

- **`specter.py`** — CLI entry point; parses arguments, builds `LLMRouter`, creates agents, and orchestrates the scan
- **`core/llm_router.py`** — Universal adapter for any OpenAI-compatible provider with retry/backoff
- **`core/agent_base.py`** — Abstract `BaseAgent` class with LLM interaction, finding aggregation, and conversation history
- **Specialised agents** (`agents/*.py`) — Inherit from `BaseAgent` and implement `run()`
- **Adaptive agents** — Can modify their own behavior based on previous findings
- **`core/session.py`** — Persists scan state as JSON under `sessions/` for resumable scans
- **`reports/reporter.py`** — Generates HTML, Markdown, and JSON reports

---

## 🛠️ Extending the Engine

1. Create a new agent file in `agents/` (e.g., `myagent.py`)
2. Subclass `BaseAgent` and implement:
```python
def run(self) -> list[Finding]:
    # perform checks, call self.add_finding(...)
    return self.findings
```
3. Register the agent in `specter.py` (add to `AGENT_MAP`)
4. Expose a CLI flag (`--agents myagent`)
5. Write unit tests and add them to the test suite

---

## 📈 Performance Tuning

- **Thread count** (`--threads N`): Start with `3`, adjust based on provider rate limits
- **Retry/back-off**: Configured in `LLMRouter.chat` (default backoff = 5s, up to 3 retries)
- **Logging level**: Set `LOG_LEVEL` env var or adjust `logging.basicConfig` in `specter.py` to `DEBUG`

---

## 📦 Dependencies

- **Python 3.11+** required
- `openai` — universal LLM client
- `pyyaml` — config parsing
- `rich` — pretty console output
- `requests`, `urllib3` — HTTP utilities
- `beautifulsoup4` — HTML parsing

---

## 🗺️ Roadmap

- [ ] Authenticated scanning (cookie/token injection)
- [ ] Subdomain enumeration
- [ ] API endpoint fuzzing
- [ ] GraphQL testing
- [ ] Nuclei template integration
- [ ] Slack/Discord notifications
- [ ] CI/CD pipeline mode

---

## ⚠️ Legal & Ethics

> **SPECTER is for authorized security testing only.**
> Only scan applications you own or have explicit written permission to test.
> Unauthorized scanning is illegal in most jurisdictions.
> The authors are not responsible for misuse.

---

## 🤝 Contributing

Pull requests are welcome! Please open an issue first to discuss changes.

---

## 📜 License

MIT — see [LICENSE](LICENSE)

---

*Built by [nvnjswaroop](https://github.com/nvnjswaroop)*
