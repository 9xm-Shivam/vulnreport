# 🔍 VulnReport — AI-Powered Vulnerability Report Generator

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![Claude AI](https://img.shields.io/badge/Claude-AI_Powered-orange)
![License](https://img.shields.io/badge/License-MIT-green)

> Enter a CVE ID or paste raw Nmap/Nessus scan output — Claude AI instantly generates a professional penetration testing report with severity rating, technical analysis, attack scenarios, and remediation steps.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🤖 **AI-Powered Analysis** | Claude AI understands CVE context and scan output |
| 📋 **Structured Reports** | Executive Summary, Technical Details, Attack Scenario, Impact, Remediation |
| 🔍 **CVE Lookup** | Enter any CVE ID (Log4Shell, EternalBlue, Heartbleed…) |
| 📄 **Scan Output Parser** | Paste raw Nmap, Nessus, or OpenVAS output |
| ⚠️ **CVSS Scoring** | Automatic severity and CVSS score assessment |
| 💾 **Export** | Copy to clipboard or save as .txt file |
| 🎯 **Sample Data** | Built-in sample Nmap and Nessus outputs to test instantly |

---

## 🗂️ Project Structure

```
vulnreport/
├── app.py                  # Flask app — routes + API endpoints
├── report_generator.py     # Claude API integration + prompt engineering
├── requirements.txt
└── templates/
    └── index.html          # Full-stack UI (input panel + report renderer)
```

---

## ⚙️ Setup

### 1. Clone and install
```bash
git clone https://github.com/9xm-shivam/vulnreport-ai.git
cd vulnreport-ai

python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS/Linux

pip install -r requirements.txt
```

### 2. Get your Anthropic API key
- Go to https://console.anthropic.com
- Create an account → API Keys → Create Key

### 3. Set the API key
```bash
# Windows PowerShell:
$env:ANTHROPIC_API_KEY="your-key-here"

# Windows CMD:
set ANTHROPIC_API_KEY=your-key-here

# macOS/Linux:
export ANTHROPIC_API_KEY="your-key-here"
```

### 4. Run
```bash
python app.py
```
Open **http://localhost:5002**

---

## 🧠 How It Works

```
User Input (CVE ID or scan output)
          │
          ▼
Flask Backend (app.py)
          │
          ▼
Structured Prompt → Claude API (claude-sonnet)
          │
          ▼
JSON Response (title, severity, cvss, sections...)
          │
          ▼
Report Rendered on Frontend
```

### Prompt Engineering
The core of the project is the system prompt in `report_generator.py`:
- Instructs Claude to act as a senior penetration tester
- Requests structured JSON output (not free text)
- Specifies all required report sections
- JSON format means each section can be rendered independently

---

## 🔌 API Endpoints

```http
POST /api/generate
{ "input_type": "cve", "content": "CVE-2021-44228", "target": "Web server" }

POST /api/generate
{ "input_type": "scan", "content": "[raw nmap output]", "target": "Internal host" }

POST /api/cve-info
{ "cve_id": "CVE-2021-44228" }
```

---

## 🗣️ Interview Q&A

**"How does the AI part work?"**
> "I send the CVE ID or scan output to the Claude API with a system prompt that tells it to act as a penetration tester. I ask it to return structured JSON with specific report sections — executive summary, technical details, attack scenario, impact, and remediation. JSON format lets me render each section cleanly instead of displaying raw text."

**"Why Claude instead of OpenAI?"**
> "Claude has strong understanding of security context and CVE descriptions. Both use the same REST API pattern — swapping models is just changing a string."

**"What is prompt engineering?"**
> "It's designing the instruction you give to the AI. In my system prompt I tell Claude exactly what role to play, what output format to use, and what fields to include. The quality of the output depends heavily on how well you design the prompt."

**"What does the backend actually do?"**
> "It takes the user input, builds the prompt, makes a POST request to the Claude API, parses the JSON response, and returns it to the frontend. Flask handles the routing and the frontend renders the sections."

---

## 🛠️ Tech Stack
Python 3.10 · Flask 3.0 · Anthropic Claude API · Vanilla JS · Zero frontend dependencies

---

## 👤 Author
**Shivam Sagore** · [GitHub](https://github.com/9xm-shivam) · [LinkedIn](https://www.linkedin.com/in/shivam-sagore/)
