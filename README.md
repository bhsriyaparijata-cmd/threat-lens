# AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform

An **AI-assisted hybrid email threat analysis platform** for investigating suspicious emails — not a basic spam classifier. It combines a machine learning model with security rules, protocol checks, network intelligence and forensic parsing into one explainable investigation workflow, with a downloadable PDF forensic report.

## Architecture at a Glance

| Component                    | Type                   | Technique                                                                              |
| ---------------------------- | ---------------------- | -------------------------------------------------------------------------------------- |
| Email content classification | **Machine Learning**   | TF-IDF + Multinomial Naive Bayes, trained on the SpamAssassin Public Corpus            |
| URL analysis                 | Rules                  | Lexical/structural heuristics (length, IP-hosts, keywords, shorteners, punycode, etc.) |
| Sender analysis              | Rules                  | From/Reply-To/Return-Path comparison, display-name checks, typosquat heuristic         |
| SPF / DKIM / DMARC           | Protocol parsing       | Parses the `Authentication-Results` header                                             |
| IP / GeoIP intelligence      | Database / API         | MaxMind GeoLite2 (optional, local) or a best-effort live lookup                        |
| Attachment analysis          | Rules (+ optional API) | Filename/MIME heuristics, SHA-256, optional VirusTotal hash lookup                     |
| Threat correlation           | Rules                  | Transparent, configurable point-based scoring (see `analyzer.py`)                      |

**Only the email-content classifier is a trained ML model.** Every other module is a documented rule, protocol check, or optional external lookup.

This project does **not** claim to be "AI trained on all datasets" — see `analyzer.py`'s `THREAT_SCORING_CONFIG` for the exact, inspectable scoring logic.

## Project Structure

```text
EmailThreatDetection/
│
├── app.py                      # Streamlit frontend
├── analyzer.py                 # Orchestration + ML loading + threat correlation
├── train_model.py              # Offline training script (SpamAssassin corpus)
├── download_dataset.py         # Downloads/extracts the SpamAssassin corpus
├── requirements.txt
├── README.md
│
├── data/
│   ├── raw/                    # Downloaded SpamAssassin corpus (spam/, ham/)
│   └── reference/              # Optional reference lists (e.g. Tranco)
│
├── model/
│   ├── spam_model.pkl          # Trained Multinomial Naive Bayes model
│   ├── vectorizer.pkl          # Fitted TF-IDF vectorizer
│   └── metrics.json            # Accuracy/precision/recall/F1/confusion matrix
│
├── reports/                    # Optional local copies of generated PDF reports
│
└── utils/
    ├── forensic_parser.py      # .eml / pasted-email parsing
    ├── url_analyzer.py         # URL heuristics
    ├── sender_analyzer.py      # Sender/header heuristics
    ├── auth_analyzer.py        # SPF/DKIM/DMARC parsing
    ├── geoip_analyzer.py       # GeoIP lookups (graceful fallback)
    ├── attachment_analyzer.py  # Attachment heuristics + optional VirusTotal
    └── pdf_report.py           # ReportLab PDF forensic report builder
```

## Setup

```bash
python -m venv venv
```

### Windows

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

Then install the required packages:

```bash
pip install -r requirements.txt
```

## 1. Download the Training Dataset

The ML component uses the SpamAssassin Public Corpus.

```bash
python download_dataset.py
```

This downloads a subset of the **SpamAssassin Public Corpus** into:

```text
data/raw/spam
data/raw/ham
```

If your environment has no internet access, download the archives manually from the SpamAssassin Public Corpus and extract them into the same folders.

## 2. Train the Model

```bash
python train_model.py
```

This is a **separate, offline step** — the Streamlit app never trains the model on startup.

It produces:

```text
model/spam_model.pkl
model/vectorizer.pkl
model/metrics.json
```

The metrics file contains information such as:

* Accuracy
* Precision
* Recall
* F1-score
* Confusion matrix

## 3. Run the Application

```bash
streamlit run app.py
```

If the model files are missing, the app still runs. The sidebar shows:

```text
ML Model: Not loaded
```

and the AI Classification section explains why, without crashing.

## Optional Configuration

| Variable        | Purpose                                                                  | Required? |
| --------------- | ------------------------------------------------------------------------ | --------- |
| `GEOIP_DB_PATH` | Path to a local MaxMind GeoLite2 `.mmdb` file for offline IP geolocation | No        |
| `VT_API_KEY`    | VirusTotal API key for attachment hash reputation lookups                | No        |

Example:

```bash
export GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb
export VT_API_KEY=your_virustotal_api_key

streamlit run app.py
```

For Windows PowerShell:

```powershell
$env:GEOIP_DB_PATH="C:\path\to\GeoLite2-City.mmdb"
$env:VT_API_KEY="your_virustotal_api_key"

streamlit run app.py
```

## Data Sources

### Training Data

* **SpamAssassin Public Corpus** — used only to train the TF-IDF + Multinomial Naive Bayes email-content classifier.

### Reference / Threat Intelligence Data

* **PhishTank (optional)** — URL threat-intelligence lookups.
* **Tranco (optional)** — reference list of well-known legitimate domains.
* **MaxMind GeoLite2 (optional/configurable)** — IP geolocation database.

GeoIP, PhishTank and VirusTotal are **reference/intelligence sources**, not ML training datasets, and are not represented as ML training data in the UI.

## Important Notes

* The ML model classifies **SPAM vs LIKELY LEGITIMATE** text patterns.
* It is **not a phishing-specific classifier** unless retrained on phishing-labeled data.
* `vectorizer.transform()` is used at inference time in `analyzer.py`, consistent with a vectorizer fitted during training.
* IP geolocation provides approximate network information and does **not** identify an attacker's exact physical location.
* No single rule, such as a suspicious URL keyword or one failed SPF check, is treated as proof of malicious intent.
* The threat score combines multiple weighted signals and displays the reasoning behind the classification.
* Uploaded attachments are **never executed**. They are inspected only as metadata such as filename, MIME type, size and SHA-256 hash.
* The application is designed to degrade gracefully when optional resources such as model files, GeoIP configuration or VirusTotal API access are unavailable.

## Forensic Analysis

The platform can analyze multiple email signals, including:

* Email headers
* Sender and recipient information
* From / Reply-To / Return-Path mismatches
* SPF, DKIM and DMARC results
* URLs and suspicious domains
* IP addresses and approximate geolocation
* Attachments and file metadata
* Email content
* Threat indicators and correlations

The results are combined into an explainable threat assessment.

## Threat Correlation

Threat correlation uses a transparent, configurable point-based scoring system.

The score considers multiple indicators rather than depending on a single signal. The final assessment provides:

* Threat score
* Risk level
* Threat type
* Detected indicators
* Supporting evidence
* Analysis reasons

This allows the user or security analyst to understand **why** an email was classified as suspicious or malicious.

## PDF Forensic Report

The platform can generate a downloadable forensic report containing information such as:

* Executive threat summary
* Threat score
* Risk level
* Threat type
* Email metadata
* Authentication results
* URL analysis
* Sender analysis
* IP and geolocation information
* Attachment information
* Threat correlation
* Investigation findings

## Disclaimer

This platform provides automated analysis and intelligence indicators.

Results should be reviewed by a qualified security analyst before taking action.
