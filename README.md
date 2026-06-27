# Threat-Informed Defense Planner

A security tool that maps threat actor techniques (MITRE ATT&CK) to defensive countermeasures (D3FEND) and cross-references your current detection/visibility coverage (DeTT&CT) to produce a prioritised remediation backlog.

**Live:** https://defence.cyberteam.uk

---

## What it does

1. Select an ATT&CK threat group (APT29, Lazarus, FIN7, etc.)
2. Upload your DeTT&CT techniques YAML (or use the included sample)
3. Click Analyse — the tool fetches D3FEND countermeasures for every technique the group uses
4. Get a prioritised gap table: **Critical / High / Medium / Low** based on your detection/visibility scores vs available defensive controls

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python / Flask |
| Frontend | Vanilla HTML/CSS/JS |
| ATT&CK data | Pre-processed STIX bundle (17 groups, 106 techniques) |
| D3FEND data | Live API at `d3fend.mitre.org` |
| DeTT&CT | YAML file upload / editor at rabobank-cdc.github.io |
| Hosting | Vercel |

---

## Deployment guide

### Prerequisites

- Git installed
- Python 3.10+ (for local dev / refreshing ATT&CK data)
- Vercel account at vercel.com
- Vercel CLI: `npm install -g vercel`
- GitHub account: github.com/jontever

---

### Step 1 — Create the GitHub repository

Run in PowerShell:

```powershell
# Navigate to the project folder
cd "C:\Users\jswin\Claude\Projects\mitre tools\threat-defense-planner"

# Initialise git
git init

# Stage everything
git add .

# Initial commit
git commit -m "feat: initial threat-informed defense planner"

# Create repo on GitHub (requires GitHub CLI: winget install GitHub.cli)
gh auth login
gh repo create threat-defense-planner --public --source=. --remote=origin --push
```

If you don't have the GitHub CLI, create the repo manually at github.com/new, then:

```powershell
git remote add origin https://github.com/jontever/threat-defense-planner.git
git branch -M main
git push -u origin main
```

---

### Step 2 — Deploy to Vercel

```powershell
# Install Vercel CLI (if not already installed)
npm install -g vercel

# Log in
vercel login

# Deploy (first time — follow prompts, accept defaults)
vercel

# Promote to production
vercel --prod
```

Vercel will give you a URL like `https://threat-defense-planner-xxx.vercel.app`.

---

### Step 3 — Point your subdomain at Vercel

In your DNS provider, add a CNAME record:

| Name | Type | Value |
|---|---|---|
| `defence` | CNAME | `cname.vercel-dns.com` |

Then in the Vercel dashboard → your project → Settings → Domains, add:

```
defence.cyberteam.uk
```

Vercel will provision a TLS cert automatically.

---

### Updating the site

After making code changes:

```powershell
cd "C:\Users\jswin\Claude\Projects\mitre tools\threat-defense-planner"

# Stage and commit changes
git add .
git commit -m "fix: description of what changed"

# Push to GitHub
git push

# Redeploy to Vercel production
vercel --prod
```

Or connect your GitHub repo in the Vercel dashboard for automatic deployments on every push to `main`.

---

### Refreshing ATT&CK data

The bundled `data/attack_data.json` was generated from MITRE ATT&CK knowledge. To pull the latest live data:

```powershell
# Install deps
pip install requests

# Run the live fetch script (downloads ~80 MB)
python scripts/fetch_data.py

# Commit the updated data file
git add data/attack_data.json
git commit -m "chore: refresh ATT&CK data"
git push
vercel --prod
```

---

### Local development

```powershell
# Create a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run the dev server
python app.py
```

Open http://localhost:5000

---

## File structure

```
threat-defense-planner/
├── app.py                    # Flask backend (API routes)
├── data/
│   └── attack_data.json      # Pre-processed ATT&CK groups + techniques
├── public/
│   ├── index.html
│   ├── css/style.css
│   ├── js/app.js
│   └── sample/
│       └── dettect_sample.yaml
├── sample/
│   └── dettect_sample.yaml   # Source copy
├── scripts/
│   ├── fetch_data.py         # Live ATT&CK data refresh (requires internet)
│   └── generate_data.py      # Regenerate from embedded knowledge
├── requirements.txt
├── vercel.json
└── .gitignore
```

---

## DeTT&CT score guide

| Score | Meaning |
|---|---|
| 0 | No visibility / detection |
| 1 | Minimal — basic log source only |
| 2 | Partial — some coverage, no tuned detection |
| 3 | Moderate — detection in place, moderate confidence |
| 4 | Good — high-confidence, low false positive rate |
| 5 | Excellent — near-complete coverage |

---

## Data sources

- [MITRE ATT&CK](https://attack.mitre.org) — adversary TTPs
- [MITRE D3FEND](https://d3fend.mitre.org) — defensive countermeasures
- [DeTT&CT Editor](https://rabobank-cdc.github.io/dettect-editor) — detection/visibility coverage YAML
