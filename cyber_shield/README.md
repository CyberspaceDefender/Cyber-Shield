# 🛡️ Cyber-Shield — AI-Powered Scam Detector in Local Languages

> *"Security warnings in the language you trust."*  
> An MVP for digital inclusion in Nigeria — real-time scam detection with alerts in Pidgin, Yorùbá, Hausa, Igbo, and English.

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Innovation & Problem Statement](#innovation--problem-statement)
3. [Technical Architecture](#technical-architecture)
4. [Features](#features)
5. [Installation & Running](#installation--running)
6. [Usage Guide](#usage-guide)
7. [Evaluation Criteria Mapping](#evaluation-criteria-mapping)
8. [Threat Detection Engine](#threat-detection-engine)
9. [Language Module](#language-module)
10. [Project Structure](#project-structure)
11. [Known Limitations & Roadmap](#known-limitations--roadmap)
12. [Security & Privacy](#security--privacy)
13. [References](#references)

---

## Project Overview

**Cyber-Shield** is a browser-based Python GUI application that scans SMS and WhatsApp messages for scams, phishing, and social engineering attacks — then explains the threat in the user's preferred Nigerian language.

Built entirely with Python's standard library (no external dependencies), it runs a local web server and opens a rich, dark-themed GUI in any browser. The system targets Nigerian users who are often victimised by scams because:

- Security warnings are written in technical English
- Many users are elderly, low-literacy, or first-time smartphone users  
- Nigerian-specific scam patterns (OTP harvesting, fake CBN grants, 419 advance-fee fraud) are not covered by generic western tools

---

## Innovation & Problem Statement

### The Digital Inclusion Gap

Nigeria has **87 million+ mobile internet users** but digital literacy remains a barrier. The EFCC reports cybercrime losses exceeding **₦8.6 billion per year**, with the majority of victims being ordinary citizens who didn't recognise the threat in time.

The core problem: **cognitive distance between the warning and the user's language of emotional trust.**

When a phishing alert says *"Phishing attempt detected — suspicious URL with lookalike domain"*, a first-time digital user who thinks in Pidgin has to:
1. Decode the technical jargon
2. Translate it mentally into their language
3. Then emotionally register the danger

By then, they've already clicked.

### Our Innovation

Cyber-Shield collapses that distance by:

- **Detecting** threats using a Nigerian-context pattern engine (not generic western phishing lists)
- **Explaining** the threat in the user's chosen language with culturally resonant examples
- **Teaching** the underlying scam tactic so users build long-term awareness
- **Covering** the four languages that together reach 90%+ of Nigeria's population

---

## Technical Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  CYBER-SHIELD MVP                      │
│                                                          │
│  ┌──────────────┐    HTTP     ┌──────────────────────┐  │
│  │   Browser    │◄──────────►│  Python HTTP Server  │  │
│  │   GUI        │  JSON API  │  (stdlib only)       │  │
│  │  (HTML/CSS/  │            │  port 8888           │  │
│  │   Vanilla JS)│            └──────────┬───────────┘  │
│  └──────────────┘                       │               │
│                                ┌────────┴────────┐      │
│                                ▼                 ▼      │
│                    ┌──────────────────┐  ┌────────────┐ │
│                    │  Threat Engine   │  │  Language  │ │
│                    │  threat_engine.py│  │  Module    │ │
│                    │                  │  │  language_ │ │
│                    │  • Pattern match │  │  module.py │ │
│                    │  • URL analysis  │  │            │ │
│                    │  • Risk scoring  │  │  Pidgin    │ │
│                    │  • 7 threat cats │  │  Yorùbá    │ │
│                    │  • False-pos     │  │  Hausa     │ │
│                    │    reduction     │  │  Igbo      │ │
│                    └──────────────────┘  │  English   │ │
│                                          └────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Component Summary

| Component | File | Responsibility |
|---|---|---|
| HTTP Server | `app.py` | Serves GUI, handles API requests |
| Threat Engine | `modules/threat_engine.py` | Pattern matching, URL analysis, risk scoring |
| Language Module | `modules/language_module.py` | Localised warning templates (5 languages × 4 verdicts) |
| GUI | Embedded in `app.py` | Dark-themed HTML/CSS/JS dashboard |

---

## Features

### Core Functionality

| Feature | Description |
|---|---|
| 🔍 **Real-time message scanning** | Paste any SMS or WhatsApp message and get instant verdict |
| 🌍 **5-language alerts** | Warnings in Pidgin, Yorùbá, Hausa, Igbo, or English |
| 🎯 **7 threat categories** | Bank impersonation, OTP harvesting, fake government, lottery, crypto fraud, romance scam, urgency manipulation |
| 🔗 **URL analysis** | Detects suspicious TLDs (.tk, .ml, .xyz), lookalike domains, IP-based URLs, URL shorteners |
| 📊 **Session statistics** | Live scan counter, scam/safe breakdown, category tracking |
| 🕐 **Scan history** | Last 8 scans with verdict and risk score |
| 💡 **Security micro-lessons** | Every scan ends with an educational tip about the tactic used |
| 📋 **4-tab result view** | Verdict, What To Do, Technical Details, Learn |
| 🧪 **6 demo messages** | Pre-loaded real-world scam examples for demonstration |

### Security Intelligence

| Threat Category | Patterns Covered | Severity |
|---|---|---|
| Bank Impersonation | GTBank, First Bank, Zenith, Access, UBA + verify/OTP language | CRITICAL |
| OTP Harvesting | Send OTP, share your PIN, enter code now | CRITICAL |
| Government Impersonation | CBN, EFCC, NIRSAL, NPower, palliative grants | HIGH |
| Lottery / Prize Scam | Won promo, processing fee, claim prize, congratulations | HIGH |
| Crypto / Investment Fraud | Guaranteed returns, BTC trading, invest and earn | HIGH |
| Romance Scam | Army/doctor abroad, package transfer, customs fee | MEDIUM |
| Urgency Manipulation | Act now, 24 hours, expires tonight, limited slots | MEDIUM |

---

## Installation & Running

### Prerequisites

- Python **3.10 or higher** (uses `list[str]` type hints)
- Any modern web browser (Chrome, Firefox, Edge, Safari)
- No pip installs required — uses Python standard library only

### Steps

```bash
# 1. Clone or download the project
git clone https://github.com/your-username/cyber-shield.git
cd cyber-shield

# 2. Run the application
python3 app.py

# 3. Browser opens automatically at:
#    http://localhost:8888
#
# If it doesn't open, navigate there manually.

# 4. To stop the server:
#    Press Ctrl+C in the terminal
```

### That's it. No pip install. No virtual environment. No API keys.

---

## Usage Guide

### Scanning a Message

1. **Choose your language** — click Pidgin, Yorùbá, Hausa, Igbo, or English at the top of the scan panel
2. **Load a demo** — use the dropdown to try pre-loaded scam examples, or paste your own text
3. **Click "Scan Message"** — results appear instantly below

### Reading the Results

The result panel has four tabs:

- **Verdict** — the main verdict (SCAM / SUSPICIOUS / CAUTION / SAFE) with localised explanation, risk score bar, and threat category badges
- **What To Do** — step-by-step action list in your chosen language (red = things to avoid, green = things to do)
- **Technical** — URL analysis details, matched pattern categories, message hash and timestamp
- **Learn** — one paragraph explaining the psychological tactic used in the scam

### Understanding Verdicts

| Verdict | Risk Score | Meaning |
|---|---|---|
| 🚨 SCAM | 60–100 | High-confidence threat. Suspicious URL + multiple patterns matched. Do not engage. |
| ⚠️ SUSPICIOUS | 22–59 | Concerning patterns without a malicious URL. Verify before acting. |
| 🟡 CAUTION | 10–21 | Minor warning signals. Proceed carefully and verify the sender. |
| ✅ SAFE | 0–9 | No threat patterns detected. Normal caution still advised. |

---

## Evaluation Criteria Mapping

### 1. Innovation (20%)

**What we built that didn't exist before:**

- Nigerian-specific threat intelligence — patterns for local scam types (NIRSAL/Npower grant fraud, MTN promo scams, GTBank/Zenith OTP harvesting) that western tools miss entirely
- Language-first security — not translation of English warnings, but *purpose-written warnings* in Pidgin, Yorùbá, Hausa, and Igbo that use culturally resonant phrasing
- Micro-learning integration — every scan ends with a one-paragraph explanation of *why* the tactic works psychologically, building long-term resilience rather than just blocking one message
- Elder-friendly framing — instructions use plain language without cybersecurity jargon (no "phishing", "spoofing", "domain lookalike" — just "dem dey pretend to be your bank")

**Novel technical decisions:**

- Positive signal detection — the engine actively detects legitimate bank transaction alerts and genuine OTP deliveries to *reduce* false positive rates, not just pattern-match for threats
- Dual-layer scoring — URL risk score + pattern weight composite, with URL presence/absence as a contextual modifier

---

### 2. Technical Quality (25%)

**Code architecture:**

- Clean separation of concerns: threat engine, language module, and server are fully independent modules
- The threat engine (`threat_engine.py`) has no knowledge of HTTP or language — it returns a pure data structure
- The language module (`language_module.py`) has no knowledge of threat scoring — it only maps verdict + language to templates
- The server (`app.py`) wires them together and handles all I/O
- Zero external dependencies — entirely portable, runs on any Python 3.10+ installation without pip

**Threat scoring design:**

```
composite_score = (
    pattern_weight × 6 × url_multiplier    # pattern contribution (max 70)
  + url_risk × 0.3                         # URL contribution (max 30)
  - positive_signals                       # reduce for legit senders
)

url_multiplier = 1.0 (if URLs present) | 0.55 (if no URL)
```

The URL multiplier prevents keyword-only matches from over-triggering on legitimate transaction alerts. The positive signal reduction (`-22` for legit sender + transaction keyword, `-30` for legit OTP delivery) was calibrated against 11 test cases covering edge cases.

**URL analysis layers:**

1. Suspicious TLD detection (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, etc.)
2. Typosquatting detection (domain contains bank name but is not the real domain)
3. Raw IP address URL detection
4. Dangerous path keywords (`/verify`, `/login`, `/secure`, `/confirm`)
5. URL shortener detection

**False positive mitigation:**

A key technical challenge in security tooling is false positives eroding user trust. We address this with:
- Legitimate Nigerian bank domain whitelist
- Transaction alert detection pattern (`debited`, `balance`, `withdrawn`) as positive signal
- OTP delivery legitimacy detection (`OTP is XXXXXX` + `do not share` + no URL)
- Isolated testing of 11 cases covering both scam and legitimate messages

---

### 3. Functionality & Usability (20%)

**Functional coverage:**

- Scans all 7 Nigerian-relevant threat categories
- Analyses URLs embedded in messages including bare `domain.tk` without `http://`
- Provides actionable guidance (not just "this is a scam" — but exactly what to do next)
- Session statistics track scan history across the session
- 6 pre-loaded demo messages cover real scam types for instant demonstration

**Usability decisions:**

- Language selector is the first UI element — users set their language before anything else
- Verdict banner uses both emoji and colour coding for accessibility
- "What To Do" tab uses universal symbols (🚫 = don't, ✅ = do) that transcend literacy levels
- Dark theme reduces eye strain for users in low-light environments (common in Nigeria)
- Single-file Python server — no installation friction whatsoever
- Mobile-responsive grid layout (single column on narrow screens)
- Auto-opens browser on startup — one command, zero steps

---

### 4. Learning Application (20%)

**Cyber concepts demonstrated:**

| Concept | Where Applied |
|---|---|
| Social engineering | Pattern detection for urgency, authority, scarcity tactics |
| Phishing | URL analysis for typosquatting, suspicious TLDs, lookalike domains |
| OTP/credential harvesting | CRITICAL severity pattern with specific countermeasures |
| Domain analysis | Multi-layer URL inspection (TLD, path keywords, IP addresses, shorteners) |
| Risk scoring | Composite weighted score combining multiple signal sources |
| False positive reduction | Positive signal detection to protect legitimate bank communications |
| Defence in depth | Pattern matching + URL analysis + sender legitimacy + context scoring |

**Educational components built into the product:**

- **Learn tab** — every scan generates a contextual explanation of the psychological tactic
- **Category explanation** — plain-language description of how the specific scam type works, in the user's language
- **Security tips sidebar** — always-visible reminders: OTP safety, domain verification, urgency as red flag
- **Technical tab** — exposes the raw analysis for users who want to understand *why* a message was flagged

---

### 5. Presentation & Clarity (15%)

**Interface clarity:**

- Result is structured into exactly 4 tabs with distinct purposes (verdict → what to do → technical → learn), preventing information overload
- Risk score bar provides instant quantitative context alongside the qualitative verdict
- Colour coding is consistent: red = danger, amber = caution, green = safe throughout all UI components
- Threat category badges immediately communicate *what kind* of threat was found
- History panel lets users compare past scans at a glance

**Code clarity:**

- Every function has a docstring explaining purpose and return value
- Constants are grouped with comments (`# Nigerian-context scam pattern database`)
- The DEMO_MESSAGES list in `app.py` serves as both working test cases and UI examples
- Module naming is self-documenting: `threat_engine`, `language_module`

---

## Threat Detection Engine

### How Scoring Works

```python
# Step 1: Pattern matching — each category has weighted keywords
for pattern in SCAM_PATTERNS:
    if any keyword matches:
        total_weight += pattern.weight   # weights 5–10

# Step 2: URL analysis — independent risk score 0–100
url_risk = max(analyse_url(u) for u in extracted_urls)

# Step 3: Composite
url_multiplier = 1.0 if urls else 0.55
pattern_score = min(total_weight × 6 × url_multiplier, 70)
composite = min(pattern_score + url_risk × 0.3, 100)

# Step 4: Positive signal reduction
if legit_sender AND transaction_alert AND no_url:
    composite -= 22
if legit_otp_delivery:
    composite -= 30

# Step 5: Verdict
SCAM       ← composite >= 60  OR (CRITICAL pattern + URL present)
SUSPICIOUS ← composite >= 22  OR (CRITICAL pattern, no URL, no positive signal)
CAUTION    ← composite >= 10
SAFE       ← composite < 10
```

### URL Risk Scoring

| Signal | Risk Added |
|---|---|
| Suspicious TLD (.tk, .ml, .xyz, etc.) | +40 |
| Typosquatting (bank name in non-bank domain) | +35 |
| Raw IP address as URL | +30 |
| URL shortener | +20 |
| Dangerous path keyword (/login, /verify) | +10 |
| Legitimate Nigerian domain | −20 |

---

## Language Module

Templates are written *natively* in each language by pattern — not machine-translated from English. Each language × verdict combination has:

- `headline` — prominent alert title
- `summary` — 1–2 sentence plain explanation
- `what_to_do` — bullet list of actions (language-specific phrasing)
- `learn` — educational explanation of the scam tactic

Additionally, 7 threat categories × 5 languages = **35 category-specific explanations** that override the generic description with a tailored explanation of exactly how that scam type works.

---

## Project Structure

```
cyber_shield/
│
├── app.py                     # Main server + embedded HTML GUI
│                              # Run this to start the application
│
├── modules/
│   ├── __init__.py
│   ├── threat_engine.py       # Scam detection, URL analysis, risk scoring
│   └── language_module.py     # Localised warning templates (5 languages)
│
└── README.md                  # This file
```

**Total: 3 Python files, ~900 lines of code, zero dependencies.**

---

## Known Limitations & Roadmap

### Current Limitations (MVP)

| Limitation | Impact | Planned Fix |
|---|---|---|
| Keyword-based detection | Cannot catch novel scam phrasings | Phase 2: integrate LLM classification via Anthropic API |
| English keyword matching | Scam messages written entirely in Yoruba/Hausa may not match | Phase 2: add native-language pattern sets |
| False positives on legit bank SMS | Some legitimate alerts score as SUSPICIOUS | Ongoing threshold calibration + user feedback loop |
| No SMS/WhatsApp integration | User must manually copy-paste messages | Phase 3: Android overlay service |
| Session-only history | Scan history lost on restart | Phase 2: local SQLite storage |
| No network threat intelligence | Cannot check URLs against live phishing databases | Phase 2: Google Safe Browsing API integration |

### Roadmap

```
Phase 1 (Current MVP)
└── Browser-based GUI, keyword engine, 5-language templates

Phase 2 — Enhanced Detection
├── LLM-powered classification (Anthropic Claude API)
├── Google Safe Browsing API for live URL checks
├── Native-language pattern sets for Yoruba/Hausa/Igbo
└── SQLite scan history persistence

Phase 3 — Mobile
├── Android accessibility service overlay
├── Real SMS/WhatsApp stream interception
└── Voice readout for low-literacy users (TTS)

Phase 4 — Community & Scale
├── Crowdsourced scam template reporting
├── USSD interface (feature phone users: forward number, get SMS reply)
└── NGO/EFCC institutional data sharing
```

---

## Security & Privacy

- **No data leaves your device.** The server runs on `localhost` only — no cloud, no telemetry, no analytics.
- **No message storage.** Scanned messages are held in memory only and cleared on server restart or when you click "Clear History".
- **No API calls.** The entire threat engine runs offline.
- **Message hashing.** Scans are identified by an 8-character MD5 hash of the message content (for deduplication only — not stored persistently).

---

## References

1. EFCC Annual Report on Cybercrime Statistics in Nigeria (2023)
2. Nigeria Communications Commission (NCC) — Digital Literacy Reports
3. Central Bank of Nigeria (CBN) Consumer Protection Framework
4. NITDA Nigeria Cybersecurity Awareness Materials
5. OWASP Phishing Detection Techniques
6. Anthropic Claude API Documentation — for Phase 2 LLM integration planning

---

## Author

**Junior Cybersecurity Analyst**  
Built for the AI-Powered Digital Inclusion Hackathon  
Nigeria, 2026

> *"The best security tool is one people actually use."*  
> Cyber-Shield meets users where they are — in the language they trust.
