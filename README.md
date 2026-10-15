# VOID // SENTINEL ❖

> **Autonomous Cyber-Deception & Honeytoken Defense Command Center**  
> *Crafted with the Kage Japanese Temple UI aesthetic & live 3D WebGL sanctuary.*

---

## ⚡ Overview

**VOID // SENTINEL** is a high-contrast, atmospheric SOC (Security Operations Center) Command Center dashboard that demonstrates autonomous cyber-deception tactics. Instead of merely blocking hostile threat actors, VOID dynamically misdirects adversaries toward synthetic honeypots, fake credentials, and honeytoken tripwires while quarantining origin IPs in real time.

The UI integrates the cinematic **Kage Kyoto Temple design system**:
- **Live 3D Sanctuary WebGL Backdrop**: Atmospheric temple, mist, and vermilion moon.
- **Kage Chapter Chips**: Four KPI metrics tracking ingress telemetry, tripped canary tokens, quarantined adversaries, and threat interception latency.
- **Real-Time Threat Telemetry Table**: Auto-ingesting event ticker, route/IP search, severity filters, and attack flash animations.
- **Intrusion Inspector**: Screen-blended flame glow card with captured payload viewer, served synthetic decoy display, and 1-click IP quarantine.
- **Canary Endpoints Panel**: Progress-tracked tripwires for `/.env`, `/admin/dump.sql`, `/api/v1/auth/tokens`, `/wp-login.php`, and `/.git/config`.
- **View Mode Switcher**: Toggle between `HUD` (high-contrast SOC), `CINEMA` (ambient blend), and `3D` (immersive temple view).

---

## 📁 Repository Structure

```text
cybersec/
├── void_dashboard.html       # Main application entry point & DOM shell
├── void-kage.html            # Standalone Kage 3D ThreeUI temple page
├── void_server.py            # Local FastAPI & Uvicorn dev server
├── requirements.txt          # Python dependencies (fastapi, uvicorn)
├── .gitignore                # Git ignore rules for clean repository
├── README.md                 # Project documentation
└── static/
    ├── css/
    │   └── void.css          # Kage design tokens, panel glass, animations & glows
    └── js/
        └── void.js           # React components, threat ticker, decoy responses & state
```

---

## 🚀 Quickstart

### 1. Prerequisites
- **Python 3.10+**

### 2. Install Dependencies
```bash
pip install -r requirements.txt
# On Windows, if 'pip' is not mapped:
py -m pip install -r requirements.txt
```

### 3. Launch the Server
```bash
python void_server.py
# On Windows:
py void_server.py
```

### 4. Access the Command Center
- **Dashboard**: [http://localhost:8080/](http://localhost:8080/)
- **Kage 3D Sanctuary**: [http://localhost:8080/kage](http://localhost:8080/kage)
- **Health Check**: [http://localhost:8080/health](http://localhost:8080/health)

---

## 🛠 Tech Stack

- **Frontend Core**: React 18 (CDN), Tailwind CSS (CDN), Babel Standalone (in-browser JSX compilation).
- **Styling & Effects**: Kage Design Tokens (`--ink`, `--bone`, `--vermilion`), custom WebGL shaders, screen-blend glows, and CSS keyframe animations.
- **3D Graphics**: Three.js WebGL procedural temple world.
- **Backend / Dev Server**: FastAPI, Uvicorn, Python.
