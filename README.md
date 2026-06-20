# 👻 PHANTOM — AI Bug Bounty Hunter

> Elite AI-powered security analysis engine for professional bug bounty hunters.  
> Built on Claude AI + real reconnaissance data for maximum accuracy.

---

## ⚡ Features

- 🌐 **Web App Analysis** — HTTP headers, DNS, SSL, subdomains, endpoints
- 📱 **Mobile App Analysis** — APK/IPA metadata, permission analysis
- 🔧 **Hardware/Firmware Analysis** — Binary analysis, architecture detection
- 🧠 **AI-Powered** — Claude analyzes real recon data, not generic assumptions
- 📊 **CVSS Scoring** — Accurate scores based on actual attack vectors
- 💰 **Bounty Estimation** — Program matching with reward ranges
- 📄 **Professional Reports** — Court-ready, submission-ready format
- 🔍 **Shodan Integration** — Real port/service/CVE data (optional)
- 🛡️ **VirusTotal Integration** — Domain reputation (optional)

---

## 🚀 Quick Start

### Option A — Local (3 commands)

```bash
git clone https://github.com/YOUR_USERNAME/phantom.git
cd phantom
cp .env.example .env        # Add your ANTHROPIC_API_KEY
pip install -r requirements.txt
python main.py
```

Open: http://localhost:8000

### Option B — Docker (1 command)

```bash
git clone https://github.com/YOUR_USERNAME/phantom.git
cd phantom
cp .env.example .env        # Add your ANTHROPIC_API_KEY
docker-compose up
```

---

## 🔑 API Keys

| Key | Required | Where to get |
|-----|----------|-------------|
| `ANTHROPIC_API_KEY` | ✅ Yes | [console.anthropic.com](https://console.anthropic.com) |
| `SHODAN_API_KEY` | Optional | [account.shodan.io](https://account.shodan.io) |
| `VIRUSTOTAL_API_KEY` | Optional | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |

---

## 📁 Project Structure

```
phantom/
├── main.py                  # FastAPI server + scan orchestration
├── config.py                # Environment & settings
├── requirements.txt         # Python dependencies
├── Dockerfile               # Container build
├── docker-compose.yml       # Full stack deployment
├── .env.example             # Environment template
├── engines/
│   ├── recon.py             # Reconnaissance (DNS, HTTP, Shodan, VT)
│   ├── ai_engine.py         # Claude AI integration
│   └── report_engine.py     # Report assembly & export
├── models/
│   └── schemas.py           # Pydantic data models
└── static/
    └── index.html           # Frontend UI
```

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | System status + configured APIs |
| `POST` | `/scan/start` | Start async scan |
| `GET` | `/scan/{id}/status` | Poll progress (0-100%) |
| `GET` | `/scan/{id}/result` | Full JSON results |
| `GET` | `/scan/{id}/report` | Plain-text report for export |
| `GET` | `/scans` | List all scans |
| `GET` | `/docs` | Swagger UI |

### Example:

```bash
# Start scan
curl -X POST http://localhost:8000/scan/start \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "target_type": "web", "scope": ["XSS", "SQLi", "SSRF"]}'

# Returns: {"scan_id": "A1B2C3D4", "status": "queued"}

# Poll status
curl http://localhost:8000/scan/A1B2C3D4/status

# Get result
curl http://localhost:8000/scan/A1B2C3D4/result
```

---

## 🐳 Deployment on VPS

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Clone & configure
git clone https://github.com/YOUR_USERNAME/phantom.git
cd phantom
cp .env.example .env
nano .env   # Add your API keys

# Run
docker-compose up -d

# Check logs
docker-compose logs -f
```

---

## ⚠️ Legal Notice

PHANTOM is designed exclusively for:
- Authorized bug bounty programs
- Targets within defined scope
- Responsible disclosure

Never use against targets without explicit authorization.

---

## 📜 License

MIT License — see [LICENSE](LICENSE)
