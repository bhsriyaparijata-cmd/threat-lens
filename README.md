# AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform

An **AI-assisted hybrid email threat analysis platform** for investigating
suspicious emails — not a basic spam classifier. It combines a machine
learning model with security rules, protocol checks, network intelligence
and forensic parsing into one explainable investigation workflow, with a
downloadable PDF forensic report.

## Architecture at a Glance

| Component | Type | Technique |
|---|---|---|
| Email content classification | **Machine Learning** | TF-IDF + Multinomial Naive Bayes, trained on the SpamAssassin Public Corpus |
| URL analysis | Rules | Lexical/structural heuristics (length, IP-hosts, keywords, shorteners, punycode, etc.) |
| Sender analysis | Rules | From/Reply-To/Return-Path comparison, display-name checks, typosquat heuristic |
| SPF / DKIM / DMARC | Protocol parsing | Parses the `Authentication-Results` header |
| IP / GeoIP intelligence | Database / API | MaxMind GeoLite2 (optional, local) or a best-effort live lookup |
| Attachment analysis | Rules (+ optional API) | Filename/MIME heuristics, SHA-256, optional VirusTotal hash lookup |
| Threat correlation | Rules | Transparent, configurable point-based scoring (see `analyzer.py`) |

**Only the email-content classifier is a trained ML model.** Every other
module is a documented rule, protocol check, or optional external lookup.
This project does **not** claim to be "AI trained on all datasets" — see
`analyzer.py`'s `THREAT_SCORING_CONFIG` for the exact, inspectable scoring
logic.

## Project Structure

```
EmailThreatDetection/
│
├── app.py                     # Streamlit frontend (4 pages)
├── analyzer.py                 # Orchestration + ML loading + threat correlation
├── train_model.py              # Offline training script (SpamAssassin corpus)
├── download_dataset.py         # Downloads/extracts the SpamAssassin corpus
├── requirements.txt
├── README.md
│
├── data/
│   ├── raw/                    # Downloaded SpamAssassin corpus (spam/, ham/)
│   └── reference/               # Optional reference lists (e.g. Tranco)
│
├── model/
│   ├── spam_model.pkl           # Trained Multinomial Naive Bayes model
│   ├── vectorizer.pkl            # Fitted TF-IDF vectorizer
│   └── metrics.json              # Accuracy/precision/recall/F1/confusion matrix
│
├── reports/                     # (optional) local copies of generated PDF reports
│
└── utils/
    ├── forensic_parser.py        # .eml / pasted-email parsing (no ML)
    ├── url_analyzer.py            # URL heuristics
    ├── sender_analyzer.py         # Sender/header heuristics
    ├── auth_analyzer.py           # SPF/DKIM/DMARC parsing
    ├── geoip_analyzer.py          # GeoIP lookups (graceful fallback)
    ├── attachment_analyzer.py     # Attachment heuristics + optional VirusTotal
    └── pdf_report.py              # ReportLab PDF forensic report builder
```

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### 1. Download the training dataset (ML component only)

```bash
python download_dataset.py
```

This downloads a subset of the **SpamAssassin Public Corpus** into
`data/raw/spam` and `data/raw/ham`. If your environment has no internet
access, download the archives manually from
<https://spamassassin.apache.org/old/publiccorpus/> and extract them into
the same folders.

### 2. Train the model

```bash
python train_model.py
```

This is a **separate, offline step** — the Streamlit app never trains on
startup. It produces `model/spam_model.pkl`, `model/vectorizer.pkl` and
`model/metrics.json` (accuracy, precision, recall, F1, confusion matrix).

### 3. Run the application

```bash
streamlit run app.py
```

If the model files are missing, the app still runs — the sidebar shows
**ML Model: Not loaded**, and the AI Classification section explains why,
without crashing.

## Optional Configuration (Environment Variables)

| Variable | Purpose | Required? |
|---|---|---|
| `GEOIP_DB_PATH` | Path to a local MaxMind GeoLite2 `.mmdb` file for offline IP geolocation | No — falls back to a best-effort live lookup, then to "GeoIP service not configured" |
| `VT_API_KEY` | VirusTotal API key for attachment hash reputation lookups | No — attachment analysis works fully without it |

Example:

```bash
export GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb
export VT_API_KEY=your_virustotal_api_key
streamlit run app.py
```

## Data Sources

- **Training data (ML):** SpamAssassin Public Corpus — used **only** to
  train the TF-IDF + Multinomial Naive Bayes email-content classifier.
- **Reference / threat-intelligence data (not ML training data):**
  - PhishTank (optional) — URL threat-intelligence lookups. Wire a lookup
    function into `analyzer.run_full_analysis(..., phishing_lookup=...)`.
  - Tranco (optional) — a reference list of well-known legitimate domains,
    useful for reducing false positives in sender/domain checks.
  - MaxMind GeoLite2 (optional/configurable) — IP geolocation database.

GeoIP and PhishTank/VirusTotal are **reference/intelligence sources**, not
ML training datasets, and are never represented as such in the UI.

## Important Notes

- The ML model classifies **SPAM vs LIKELY LEGITIMATE** text patterns. It
  is **not** a phishing-specific classifier unless retrained on
  phishing-labeled data.
- `vectorizer.transform()` (never `fit_transform()`) is used at inference
  time in `analyzer.py`, consistent with a vectorizer fit once during
  training.
- IP geolocation is approximate network information — it does **not**
  identify an attacker's exact physical location.
- No single rule (a URL keyword, a header mismatch, one failed SPF check)
  is treated as proof of malicious intent; the threat score combines
  multiple weighted signals and always shows its reasoning.
- Uploaded attachments are **never executed**; they are only inspected as
  metadata (filename, MIME type, size, hash).
- Every module degrades gracefully: missing model files, missing GeoIP
  configuration, missing VirusTotal key, malformed headers, or emails with
  no URLs/attachments/authentication data will never crash the app.

## Disclaimer

This platform provides automated analysis and intelligence indicators.
Results should be reviewed by a qualified security analyst before taking
action.
