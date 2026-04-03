# 🏦 NBFC AI — Smart Lending Platform

An AI-powered loan analysis platform for NBFCs built with FastAPI + Claude AI.  
Deploy in minutes on Railway.app.

---

## ✨ Features

- ⚡ **Instant Loan Analysis** — AI evaluates applications in seconds
- 🎯 **Risk Scoring** — Low / Medium / High risk classification
- 🚨 **Fraud Detection** — AI flags suspicious patterns automatically
- 💡 **Explainable Decisions** — Plain English reasons for approval/rejection
- 📊 **DTI Calculation** — Debt-to-income ratio analysis
- 🔒 **RBI-friendly** — Explainable AI for compliance

---

## 🚀 Deploy on Railway (5 minutes)

### Step 1 — Push to GitHub

```bash
git init
git add .
git commit -m "Initial commit — NBFC AI Platform"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/nbfc-ai-platform.git
git push -u origin main
```

### Step 2 — Deploy on Railway

1. Go to [railway.app](https://railway.app) and sign in with GitHub
2. Click **New Project** → **Deploy from GitHub repo**
3. Select your `nbfc-ai-platform` repository
4. Railway will auto-detect and build the app

### Step 3 — Add Environment Variable

In Railway dashboard:
1. Click your project → **Variables** tab
2. Add: `ANTHROPIC_API_KEY` = `your_key_here`
3. Get your API key from [console.anthropic.com](https://console.anthropic.com)

### Step 4 — Go Live! 🎉

Railway gives you a public URL like:  
`https://nbfc-ai-platform-production.up.railway.app`

---

## 💻 Run Locally

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/nbfc-ai-platform.git
cd nbfc-ai-platform

# Install dependencies
pip install -r requirements.txt

# Set your API key
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# Run the server
uvicorn main:app --reload --port 8000

# Open browser
# http://localhost:8000
```

---

## 🏗️ Project Structure

```
nbfc-ai-platform/
├── main.py              # FastAPI backend + Claude AI logic
├── templates/
│   └── index.html       # Frontend UI (single page)
├── requirements.txt     # Python dependencies
├── railway.toml         # Railway deployment config
├── .env.example         # Environment variables template
├── .gitignore
└── README.md
```

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python) |
| AI | Anthropic Claude (claude-sonnet-4) |
| Frontend | HTML + CSS + Vanilla JS |
| Deployment | Railway.app |
| Templates | Jinja2 |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Main UI |
| POST | `/analyze-loan` | AI loan analysis |
| GET | `/health` | Health check |

---

## 🤝 Built by

Powered by Claude AI · Designed for Indian NBFC market
