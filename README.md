# MAILGUARD / TRACE-AI

**AI-Assisted Email Threat Detection & Forensic Intelligence Platform**

MailGuard (TRACE-AI) is a full-stack cybersecurity platform engineered to identify sophisticated phishing, spoofing, and malicious communications. It combines deep RFC 822 MIME parsing, cryptographic email authentication verification, received-chain network hop reconstruction, machine learning text classification, domain typosquatting detection, and graph-based threat correlation (Neo4j).

---

## ⚡ Core Architecture & Pipeline

```text
Incoming Email (.eml / raw text)
        │
        ▼
[1] Ingestion & Parsing
    ├── RFC 822 / MIME Multi-part Parsing
    ├── Header Extraction (From, Return-Path, Reply-To, Message-ID)
    └── URL & Domain Extractor
        │
        ▼
[2] Forensics Engine
    ├── Cryptographic Authentication (SPF, DKIM, DMARC Validation)
    └── Received-Chain Network Hop Reconstruction (Relay tracing & latency)
        │
        ▼
[3] Threat Intelligence & Lookalike Analysis
    ├── IP Intelligence & Geo-correlation
    ├── Domain WHOIS / DNS & Reputation Analysis
    └── Lookalike / Typosquatting Domain Analysis (Levenshtein & homoglyphs)
        │
        ▼
[4] Machine Learning & Language Intelligence
    ├── TRACE-AI TF-IDF + Logistic Regression / Random Forest Text Classifier
    └── Urgency & Social Engineering NLP Heuristics
        │
        ▼
[5] Evidence Fusion & Risk Engine
    └── Multi-Signal Fusion Scoring -> Verdict (CLEAN / SUSPICIOUS / MALICIOUS)
        │
        ▼
[6] Graph Correlation & Threat Telemetry (Neo4j)
    └── IOC Mapping (Campaigns, IPs, Domains, Senders, Hashes)
```

---

## 🚀 Key Features

- **Multi-Factor Email Forensics**: Validates SPF records, DKIM cryptographic signatures, and DMARC policies; flags misalignments and spoofing attempts.
- **Received Hop Analysis**: Parses `Received:` headers to track relay hops, detect forged headers, private IP anomalies, and anomalous transport delays.
- **Domain Lookalike Detector**: Flags homoglyph attacks, punycode spoofing, and typosquatting targeting trusted entities.
- **TRACE-AI ML Engine**: Pre-trained machine learning pipeline evaluating email text against thousands of real-world spam and phishing samples.
- **Neo4j Graph IOC Correlation**: Links emails, sender domains, relay IPs, and extracted URLs to uncover coordinated phishing campaigns.
- **Evaluation Lab & Interactive UI**: An International Typographic (Swiss-style) web interface featuring a live evaluation benchmark, interactive threat scanner, and architectural forensic viewer.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.9+, FastAPI, Uvicorn, Pydantic, Scikit-Learn, Joblib, Pandas, NumPy
- **Graph Database**: Neo4j (Cypher query language)
- **Forensics / Network**: dnspython, python-multipart, email parsing libraries
- **Frontend**: HTML5, Vanilla Modern CSS, JavaScript (ES6+), Swiss Grotesque typography

---

## 🏁 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/KarthikIsCodingNow/MailGuard.git
cd MailGuard
```

### 2. Environment Setup
```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy the example environment configuration:
```bash
cp backend/.env.example backend/.env
```
Update `backend/.env` with your Neo4j connection details (if utilizing graph correlation):
```env
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_password
```

### 4. Run the Platform
Start the FastAPI server:
```bash
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

Access the application in your browser:
- **Web Interface**: `http://localhost:8000`
- **Interactive API Docs (Swagger)**: `http://localhost:8000/docs`
