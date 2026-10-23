# SecurePass — Password Security & Breach-Risk Checker

[![Tests](https://img.shields.io/badge/tests-50%20passed-10b981.svg)](#5-automated-testing)
[![Python](https://img.shields.io/badge/python-3.10%2B-00f2fe.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.0%2B-0df2c9.svg)](https://flask.palletsprojects.com/)
[![k-Anonymity](https://img.shields.io/badge/k--Anonymity-HIBP%20API-14f195.svg)](https://haveibeenpwned.com/API/v3#PwnedPasswords)

**SecurePass** is a privacy-first cybersecurity hackathon dashboard that analyzes password strength, flags predictable patterns (sequences, keyboard walks, dictionary roots, and repetitions), and checks for known breach exposures using **k-Anonymity** without ever exposing or storing the submitted credential.

---

## 1. Compulsory Requirements Traceability Matrix

Every official hackathon problem requirement is implemented and verified as follows:

| # | Compulsory Requirement | Implementation File(s) | Verification & Tests |
|---|---|---|---|
| **1** | Evaluate length, common patterns & estimated strength locally | [`strength_engine.py`](file:///c:/Users/Abhishek/OneDrive/Desktop/SecurePass/strength_engine.py) | [`tests/test_strength_engine.py`](file:///c:/Users/Abhishek/OneDrive/Desktop/SecurePass/tests/test_strength_engine.py) (14 unit tests) |
| **2** | Use privacy-preserving breach check or labeled mock dataset | [`breach_checker.py`](file:///c:/Users/Abhishek/OneDrive/Desktop/SecurePass/breach_checker.py), [`static/app.js`](file:///c:/Users/Abhishek/OneDrive/Desktop/SecurePass/static/app.js) | [`tests/test_breach_checker.py`](file:///c:/Users/Abhishek/OneDrive/Desktop/SecurePass/tests/test_breach_checker.py) (10 tests) |
| **3** | Never log or store submitted passwords | [`app.py`](file:///c:/Users/Abhishek/OneDrive/Desktop/SecurePass/app.py), [`static/app.js`](file:///c:/Users/Abhishek/OneDrive/Desktop/SecurePass/static/app.js) | [`tests/test_privacy_safeguards.py`](file:///c:/Users/Abhishek/OneDrive/Desktop/SecurePass/tests/test_privacy_safeguards.py) (8 automated tests) |
| **4** | Give actionable suggestions to improve passwords | [`strength_engine.py`](file:///c:/Users/Abhishek/OneDrive/Desktop/SecurePass/strength_engine.py) | Dynamic mapping of detected weaknesses to suggestions |
| **5** | Test with common weak and strong examples | `tests/` directory (50 tests) | Tested: `123456`, `password123`, `qwerty`, `12345678`, `AAAAAA`, passphrases |

---

## 2. Architecture & Privacy-First Flow

SecurePass strictly adheres to the principle of **Zero-Knowledge Privacy by Design**:

```
[ Browser UI ]
      │
      ├── 1. Strength Analysis (Local network only)
      │      └─► [ Flask POST /api/analyze ] ──► [ strength_engine.py ]
      │
      └── 2. Breach Intelligence (k-Anonymity Protocol)
             ├─► Browser computes SHA-1 locally (Web Crypto API or fallback)
             ├─► Slices first 5 hexadecimal characters (Prefix)
             │
             └─► [ Flask GET /api/breach-check?prefix=5BAA6 ]
                     │
                     ▼
             [ HIBP Pwned Passwords Range API ]
                     │ (Returns ~800 anonymous suffixes)
                     ▼
             [ Browser UI ]
                     └─► Compares remaining 35-character suffix locally
                     └─► Updates verified occurrence count & threat state
```

### Critical Security Safeguards
1. **k-Anonymity Range Querying:** The backend and HIBP receive only a 5-character SHA-1 prefix (e.g. `5BAA6`). The raw password and full hash never leave client memory.
2. **Zero Storage Policy:** Passwords and hashes are never written to `localStorage`, `sessionStorage`, cookies, databases, or log files.
3. **Honest Multi-State Transparency:** The UI distinctly differentiates 5 independent states:
   - `Not checked`: Initial idle state.
   - `Checking`: Outbound prefix range lookup active.
   - `Match found`: Local suffix match verified in returned range.
   - `No match found`: Target suffix absent from returned range.
   - `Unable to check`: Network or upstream failure (*never falsely reported as "safe"*).
4. **Offline Demo Mode Resilience:** If offline presentation is necessary, the API supports an isolated fixture dataset (`?demo=1` or `SECUREPASS_DEMO_MODE=1`) prominently marked as `DEMO DATA — NOT A REAL BREACH CHECK`.

---

## 3. Project File Structure

```
SecurePass/
├── app.py                     # Flask application server & REST routing
├── strength_engine.py         # Heuristic password strength analysis engine
├── breach_checker.py          # HIBP range API client with prefix validation
├── requirements.txt           # Python dependencies (Flask, pytest)
├── README.md                  # Comprehensive documentation & demo guide
├── .gitignore                 # Standard Python, environment & cache ignore
├── index.html                 # Direct root entry point for local previews
├── templates/
│   └── index.html             # Dashboard UI template matching reference screenshot
├── static/
│   ├── style.css              # Cyber dark theme, neon glows, responsive grid
│   └── app.js                 # Web Crypto hashing, REST calls, UI interactions
└── tests/
    ├── test_strength_engine.py    # Specific weak, sequence & strong test cases
    ├── test_breach_checker.py     # Range API prefix, timeouts & demo labeling
    ├── test_app.py                # Flask routes, status codes & CORS preflight
    ├── test_privacy_safeguards.py # Zero-logging, prefix enforcement & storage checks
    └── test_e2e_integration.py    # Live server end-to-end integration tests
```

---

## 4. Windows 11 Quickstart Guide

### Prerequisites
- Windows 11 with Python 3.10+ installed.
- Visual Studio Code (or your preferred editor).

### Step-by-Step Installation

1. **Open the project folder in VS Code:**
   Open VS Code and navigate to `SecurePass`.

2. **Open integrated PowerShell:**
   Press `` Ctrl + ` `` to open PowerShell in the project directory.

3. **Create a virtual environment:**
   ```powershell
   py -m venv .venv
   ```

4. **Activate the virtual environment:**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
   > **Note for PowerShell execution policy:** If PowerShell blocks script execution, run this safe one-time command in the current terminal:
   > ```powershell
   > Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   > .\.venv\Scripts\Activate.ps1
   > ```
   > You can also run commands directly using `.\.venv\Scripts\python.exe` without activating the shell!

5. **Install dependencies:**
   ```powershell
   python -m pip install -r requirements.txt
   ```

6. **Start the application:**
   ```powershell
   python app.py
   ```
   *(Or `.\.venv\Scripts\python.exe app.py`)*

7. **Open the application in your browser:**
   Navigate to:
   ```
   http://127.0.0.1:5000
   ```

---

## 5. Automated Testing

SecurePass includes **50 automated unit, integration, and security verification tests**.

### Run all tests with pytest:
```powershell
.\.venv\Scripts\python.exe -m pytest -v tests
```

### Run all tests with standard unittest:
```powershell
.\.venv\Scripts\python.exe -m unittest discover tests
```

---

## 6. Offline / Demo Mode (Optional)

If presenting in an offline environment where internet access is unavailable:
1. Set the environment variable:
   ```powershell
   $env:SECUREPASS_DEMO_MODE="1"
   python app.py
   ```
2. Or append `?demo=1` to the breach endpoint.
3. The UI will prominently display the required label:
   **`DEMO DATA — NOT A REAL BREACH CHECK`**
   ensuring mock data is never presented as a real API result.

---

## 7. Live Hackathon Demonstration Script (Judge-Ready)

Follow this 2-minute walkthrough during your project presentation:

| Step | Test Credential | What to Highlight to Judges |
|---|---|---|
| **1. UI & Health** | *(Empty state)* | Point out the real-time backend connection status dot (`Backend connected`), cybersecurity dark aesthetics, and privacy notice. |
| **2. Trivial Weak** | `123456` | - Score: 18 / 100 (`Very Weak`).<br>- Flagged: Common weak password and ascending numerical sequence.<br>- Breach check: **18+ Million** verified breach occurrences. |
| **3. Common Pattern** | `password123` | - Checklist updates (2/5).<br>- Flagged: Common root `'password1'` and sequence `'123'`.<br>- Radar turns red: **52+ Million** occurrences. |
| **4. Keyboard Walk** | `qwerty` | - Flagged: Predictable keyboard walk pattern.<br>- Score capped at 18 / 100 (`Very Weak`). |
| **5. Sequence & Repetition** | `AAAAAA` or `12345678` | - Flagged: Excessive repeated characters (`AAAAAA`) or predictable sequence.<br>- Specific actionable remediation suggestions displayed. |
| **6. Strong Passphrase** | `Solar#Flare$Cascade88` or `Correct-Horse-Battery-Staple-2026!` | - Checklist updates to 5/5.<br>- Score: 90 / 100 (`Very Strong`).<br>- High entropy calculation (>120 bits).<br>- Breach check finds **0 matches** (green safe state). |
| **7. Privacy Proof** | *(DevTools F12)* | Open the **Network** tab in browser DevTools. Show that `/api/breach-check?prefix=5BAA6` only transmits the 5-character prefix. The raw password was never sent over HTTP for breach checking. |

---

## 8. Submission Details
- **Project:** SecurePass — Password Security & Breach-Risk Checker
- **Submission Date:** October 2026
- **License:** MIT License
