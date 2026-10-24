# 🛡️ PromptGuard — AI Firewall & LLM Data Leakage Prevention Gateway

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Presidio](https://img.shields.io/badge/Microsoft-Presidio-0078D4.svg)](https://github.com/microsoft/presidio)
[![PyTorch](https://img.shields.io/badge/PyTorch-Transformers-EE4C2C.svg)](https://pytorch.org/)
[![PyMuPDF](https://img.shields.io/badge/PyMuPDF-PDF%20Redaction-red.svg)](https://pymupdf.readthedocs.io/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32%2B-FF4B4B.svg)](https://streamlit.io/)
[![Chrome Extension](https://img.shields.io/badge/Extension-Manifest%20V3%20v2.1-4285F4.svg)]()
[![Tests](https://img.shields.io/badge/Tests-40%20Passed-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

**PromptGuard** is an enterprise-grade application-layer security gateway and Data Leakage Prevention (DLP) firewall designed for Large Language Model (LLM) architectures. It operates as an intelligent reverse-proxy, browser interceptor, and media sanitizer between client applications/users and upstream LLMs (e.g., OpenAI, Anthropic Claude, Google Gemini, Groq, Mistral AI, Cohere, or self-hosted LLMs), intercepting prompts and attachments in real time to inspect, redact sensitive data, and block malicious adversarial attacks.

---

## 📑 Table of Contents

- [✨ Key Features](#-key-features)
- [🏗️ Core Architecture & Flow](#-core-architecture--flow)
- [🔍 Multi-Stage Detection Pipeline](#-multi-stage-detection-pipeline)
- [🖼️ Visual Media & Document Redaction Engine](#️-visual-media--document-redaction-engine)
- [⚖️ Policy Decision Engine](#-policy-decision-engine)
- [💻 Client Interfaces & Demos](#-client-interfaces--demos)
  - [1. Attack Demonstration & Simulation Page (`/demo`)](#1-attack-demonstration--simulation-page-demo)
  - [2. Multi-Provider PromptGuard Chat UI (`/chat`)](#2-multi-provider-promptguard-chat-ui-chat)
  - [3. Dual-Layer Chrome Browser Extension (ChatGPT, Claude, Gemini, Mistral, Groq, Cohere)](#3-dual-layer-chrome-browser-extension)
  - [4. Interactive Security Dashboard (`:8501`)](#4-interactive-security-dashboard-8501)
- [📁 Project Directory Structure](#-project-directory-structure)
- [🚀 Quick Start & How to Run](#-quick-start--how-to-run)
  - [Prerequisites](#prerequisites)
  - [1. Installation & Environment Setup](#1-installation--environment-setup)
  - [2. Running the AI Firewall Gateway (Port 8000)](#2-running-the-ai-firewall-gateway-port-8000)
  - [3. Running the Streamlit Security Dashboard (Port 8501)](#3-running-the-streamlit-security-dashboard-port-8501)
  - [4. Installing & Using the Chrome Browser Extension](#4-installing--using-the-chrome-browser-extension)
- [📡 API Reference](#-api-reference)
  - [1. Chat UI Endpoint (`POST /api/chat`)](#1-chat-ui-endpoint-post-apichat)
  - [2. Attack Demo Unprotected Endpoint (`POST /api/demo/unprotected`)](#2-attack-demo-unprotected-endpoint-post-apidemounprotected)
  - [3. Prompt & Media Inspection Endpoint (`POST /api/inspect`)](#3-prompt--media-inspection-endpoint-post-apiinspect)
  - [4. OpenAI-Compatible Proxy (`POST /v1/chat/completions`)](#4-openai-compatible-proxy-post-v1chatcompletions)
  - [5. Audit Logs (`GET /api/audit-logs`)](#5-audit-logs-get-apiaudit-logs)
  - [6. Analytics (`GET /api/analytics`)](#6-analytics-get-apianalytics)
- [🧪 Running Automated Tests](#-running-automated-tests)
- [🔒 Audit & Compliance Logging](#-audit--compliance-logging)
- [📄 License](#-license)

---

## ✨ Key Features

* 🔒 **4-Stage Threat Inspection**: Comprehensive detection covering PII/Identity, Credentials & Secrets, Financial Data, and Transformer-based Jailbreaks/Adversarial Intent.
* 🖼️ **In-Place Visual Media Pixel Redaction**:
  * **Images (`.png`, `.jpg`, `.webp`, `.bmp`, `.gif`)**: Word-level OCR bounding box mapping via Tesseract and Pillow paints black redaction boxes directly over sensitive text pixels.
  * **PDFs (`.pdf`)**: Native vector search and black-box visual redaction via PyMuPDF (`fitz`), with fail-closed safety blanking for unlocatable spans.
  * **Documents & Code (`.docx`, `.xlsx`, `.pptx`, `.odt`, `.csv`, `.txt`, `.json`, `.yaml`, `.py`, etc.)**: Extracted text with deterministic entity tag replacements.
* 🌐 **Dual-Layer Browser Extension (Manifest V3 v2.1.0)**:
  * **MAIN World Fetch Interceptor (`fetch_interceptor.js`)**: Hooks `window.fetch` at `document_start` to intercept API calls across ChatGPT, Claude.ai, Gemini, Mistral, Groq, and Cohere. Rewrites request bodies on `REDACT` or aborts on `BLOCK`.
  * **ISOLATED World UI Overlay (`content.js`)**: Intercepts keyboard events, send buttons, clipboard paste, and drag-and-drop file inputs.
  * **One-Click Sanitized Media Download**: When attachments contain sensitive data, users can download the pixel-redacted image or sanitized PDF directly and upload the safe copy without refreshing.
* 🤖 **Multi-Provider LLM Gateway**: Native support and multimodal payload translation for OpenAI (`gpt-4o`, `gpt-4.1`), Anthropic Claude (`claude-sonnet-4`, `claude-3-5-haiku`), Google Gemini (`gemini-2.5-pro`, `gemini-2.0-flash`), Groq (`llama-3.3-70b`), Mistral AI, Cohere, and local/custom endpoints.
* 🖥️ **Interactive Chat UI with "Media Before and After"**: Dark-themed ChatGPT-style web interface with instant security verdicts, inline badges, drag-and-drop attachments, and side-by-side visual comparisons of original vs. pixel-redacted images.
* 🎮 **Interactive Attack Demonstration Mode**: Built-in side-by-side simulator showing prompt leakage vs. PromptGuard active mitigation.
* 📊 **Security Operations Dashboard**: Streamlit-powered audit explorer, threat metrics, and interactive prompt testing sandbox.
* ⚡ **OpenAI SDK Compatible**: Drop-in reverse proxy replacement for `/v1/chat/completions`.

---

## 🏗️ Core Architecture & Flow

```mermaid
flowchart TD
    subgraph Clients [Clients & Interceptors]
        ExtMain[Chrome Extension: Fetch Interceptor (MAIN World)]
        ExtUI[Chrome Extension: Content Script (ISOLATED World)]
        ChatUI[PromptGuard Chat UI :8000/chat]
        DemoUI[Attack Demo Simulator :8000/demo]
        SDK[OpenAI SDK / LangChain / Apps]
    end

    Clients -->|Prompt + Media Attachments| Gateway[FastAPI Firewall Gateway :8000]

    subgraph Ingestion [Media Extraction & Normalization]
        Decoder[Multi-Encoding Preprocessor\nBase64 / Hex / ROT13 / URL]
        Extractor[Media Content Extractor\nTesseract OCR / PyPDF2 / OOXML / Plaintext]
    end

    Gateway --> Ingestion

    subgraph Pipeline [4-Stage Threat Detection Pipeline]
        S1[Stage 1: PII & Identity\nPresidio + Regex + spaCy NER]
        S2[Stage 2: Credentials & Secrets\nRegex + Entropy + GLiNER Zero-Shot]
        S3[Stage 3: Financial & Payment DLP\nCredit Cards + Luhn + CVV + IFSC]
        S4[Stage 4: Adversarial Intent & Jailbreaks\nPyTorch Transformers + DeBERTa / RoBERTa]
    end

    Ingestion --> Pipeline
    Pipeline --> Engine{Policy Decision Engine}

    subgraph Actions [Policy Enforcement]
        Engine -->|BLOCK| BlockAction[HTTP 403 / Abort Fetch / Security Block Modal]
        Engine -->|REDACT| RedactAction[Deterministic Tag Redaction + Visual Media Sanitizer]
        Engine -->|ALLOW| AllowAction[Forward Clean Payload]
    end

    subgraph VisualRedaction [Media Redaction Engine]
        RedactAction --> Pillow[Pillow: Image Pixel Redaction Boxes]
        RedactAction --> PyMuPDF[PyMuPDF: PDF Visual Redaction Annotations]
        RedactAction --> DocSanitize[Doc / Text Redacted Snippets]
    end

    subgraph UpstreamForwarding [Multimodal Upstream Dispatcher]
        VisualRedaction --> MultimodalPayload[Build Multimodal Payload\nOpenAI / Anthropic / Gemini Formats]
        AllowAction --> MultimodalPayload
        MultimodalPayload --> UpstreamLLM[Upstream LLM: OpenAI / Claude / Gemini / Groq / Local]
    end

    UpstreamLLM --> Gateway
    Gateway --> Clients

    Gateway -.->|Structured Audit Events| SQLite[(SQLite DB & audit.log)]
    SQLite -.-> Dashboard[Streamlit Security Dashboard :8501]
```

---

## 🔍 Multi-Stage Detection Pipeline

PromptGuard runs a sequential 4-stage inspection pipeline with multi-encoding preprocessing and comprehensive media extraction:

| Stage | Name | Target Threats & Entities | Detection Engine |
| :--- | :--- | :--- | :--- |
| **Stage 1** | **PII & Identity** | Names, Email addresses, Phone numbers, Dates of Birth, Locations, Indian National IDs (Aadhaar, PAN, Passport) | Microsoft Presidio Analyzer + Custom Regex Pattern Matchers + spaCy NER (`en_core_web_sm`) |
| **Stage 2** | **Credentials & Secrets** | AWS Access/Secret Keys, JWT tokens, Database connection URIs (User/Pass/Host), Stripe Secret Keys, SendGrid API Keys, Superadmin credentials | High-entropy Regex Scanners + Shannon Entropy / Token Shape Heuristics + GLiNER Zero-Shot Model |
| **Stage 3** | **Financial & Payment DLP** | Credit Card numbers (Visa, Mastercard, Amex, RuPay), Card Expiry dates, CVVs, Bank Account numbers, IFSC codes | Luhn Algorithm Checksum Validator + Financial Regex Scanners |
| **Stage 4** | **Adversarial Intent & Jailbreaks** | Prompt Injections (system overrides, delimiter attacks), Jailbreaks (DAN, Developer Mode), Bulk PII extraction attempts, Material Non-Public Information (MNPI) exfiltration, Roleplay bypasses, Command Injections | PyTorch Neural Intent Classification Model + Hugging Face Transformers Pipeline + Obfuscation Decoders |

---

## 🖼️ Visual Media & Document Redaction Engine

When media files are attached or pasted, PromptGuard extracts their text, runs the full 4-stage pipeline, and performs **true visual pixel redaction** before any payload is forwarded upstream or returned to the client:

```mermaid
flowchart LR
    File[Attached Image / PDF / Doc] --> DetectMime[MIME Resolution]
    DetectMime -->|Images: PNG, JPG, WebP| OCR[Tesseract OCR\nWord-Level Coordinates]
    DetectMime -->|PDF: application/pdf| PyPDF[PyPDF2 Text Extraction\n+ PyMuPDF fitz Search]
    DetectMime -->|DOCX / XLSX / PPTX / ODT| OOXML[Office Open XML Extractor]
    DetectMime -->|CSV / Code / Text| DirectRead[Direct Strict UTF-8/16 Decoder]

    OCR --> Findings[Stage 1-4 Pipeline Findings]
    PyPDF --> Findings
    OOXML --> Findings
    DirectRead --> Findings

    Findings -->|Image Match| PILDraw[Pillow ImageDraw: Paint Black Bounding Boxes]
    Findings -->|PDF Match| FitzRedact[PyMuPDF fitz.Page.add_redact_annot: Black Fill]
    Findings -->|Doc Match| SnippetRedact[Deterministic Tag Replacement]

    PILDraw --> SanitizedOut[Sanitized Output: Base64 Data URI + Multimodal Forwarding + One-Click Download]
    FitzRedact --> SanitizedOut
    SnippetRedact --> SanitizedOut
```

* **Image Pixel Redaction**: PyTesseract locates OCR bounding boxes of matched sensitive snippets; Pillow draws filled black rectangles over the coordinates and exports a sanitized PNG data URI.
* **PDF Redaction**: PyMuPDF searches for text bounding boxes and applies permanent redaction annotations (`fitz.Page.apply_redactions()`). If coordinate matching fails, the engine safely blanks the affected page or document rather than leaking sensitive text.
* **Fail-Closed Guarantee**: If a file contains sensitive data that cannot be cleanly redacted, or if an unsupported binary format is uploaded, PromptGuard strips the attachment and notifies the user rather than passing uninspected data.

---

## ⚖️ Policy Decision Engine

The Policy Engine assigns risk severities (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and enforces one of three actions:

- **`ALLOW`**: Zero sensitive entities or threats detected. The request and any clean attachments are forwarded upstream unchanged.
- **`REDACT`**: Sensitive identifiers are replaced with deterministic tags, and media files are pixel-redacted before forwarding:
  - `[EMAIL_ADDRESS]`, `[PHONE_NUMBER]`, `[NAME]`, `[DATE_OF_BIRTH]`, `[LOCATION]`
  - `[AADHAAR_REDACTED]`, `[PAN_REDACTED]`, `[PASSPORT_REDACTED]`
  - `[CREDIT_CARD_REDACTED]`, `[EXPIRY_REDACTED]`, `[CVV_REDACTED]`, `[BANK_ACCOUNT_REDACTED]`, `[IFSC_REDACTED]`
  - `[AWS_ACCESS_KEY_REDACTED]`, `[AWS_SECRET_KEY_REDACTED]`, `[JWT_TOKEN_REDACTED]`, `[DB_USER_REDACTED]`, `[DB_PASSWORD_REDACTED]`, `[DB_HOST_REDACTED]`
- **`BLOCK`**: Malicious adversarial intent (Stage 4) or critical multi-secret exposures (superadmin credentials, root passwords, confidential MNPI) trigger an immediate block. The upstream LLM is never invoked.

---

## 💻 Client Interfaces & Demos

### 1. Attack Demonstration & Simulation Page (`/demo`)
A live side-by-side attack visualizer designed for presentations, team demos, and security evaluations:
* **URL**: `http://localhost:8000/demo`
* **Features**:
  * **5 One-Click Attack Scenarios**: PII Leakage, Credential Exposure, Financial Data Leak, Jailbreak Attack, and Obfuscated / Encoded Injections.
  * **Parallel Execution**: Simulates what happens **WITHOUT PromptGuard** (left panel, red) vs. **WITH PromptGuard** (right panel, green).
  * **Interactive Pipeline Stages**: Visualizes which stage caught the threat, detection entities, and response times.

### 2. Multi-Provider PromptGuard Chat UI (`/chat`)
A standalone ChatGPT-style application served directly from the gateway:
* **URL**: `http://localhost:8000/chat`
* **Features**:
  * **Multi-LLM Support**: Switch seamlessly between OpenAI, Anthropic Claude, Google Gemini, Groq, Mistral AI, Cohere, and Custom OpenAI-compatible backends.
  * **API Key Controls**: Enter API keys in the client UI or configure them server-side in `.env`.
  * **File & Media Uploads**: Drag-and-drop or clipboard paste for Images, PDFs, Word DOCX, Excel XLSX, PPTX, ODT, CSV, and source code files.
  * **Media Before and After Panel**: Interactive side-by-side visualizer showing the original uploaded image next to the pixel-redacted version, along with detection chips and sanitized document previews.
  * **Inline Security Badges**: Real-time `ALLOW`, `REDACT`, or `BLOCK` indicators with latency and policy violation details.

### 3. Dual-Layer Chrome Browser Extension
A Manifest V3 browser extension (v2.1.0) providing real-time interception on popular web LLMs:
* **Supported Sites**: ChatGPT (`chatgpt.com`), Claude (`claude.ai`), Google Gemini (`gemini.google.com`), Mistral AI (`chat.mistral.ai`), Groq Console (`console.groq.com`), and Cohere Coral (`coral.cohere.com`).
* **Dual-Architecture**:
  1. **Fetch Interceptor (`fetch_interceptor.js`)**: Injected into the page's `MAIN` world at `document_start`. Hooks `window.fetch` to intercept outgoing LLM conversation requests directly at the transport layer. Rewrites prompts on `REDACT` or aborts requests on `BLOCK`.
  2. **Content Script (`content.js`)**: Runs in the `ISOLATED` world. Intercepts UI submission events, file picker uploads, drag-and-drop files, and clipboard pasted images.
* **One-Click Sanitized Media Download**:
  * When an uploaded image or PDF contains sensitive data, the PromptGuard overlay alerts the user with detected entities.
  * Provides a direct **"Download sanitized [filename]"** button.
  * Cleans the dirty file from the chat composer, enabling the user to attach the downloaded sanitized copy immediately without refreshing the page!

### 4. Interactive Security Dashboard (`:8501`)
A Streamlit analytics dashboard for Security & Compliance teams:
* **URL**: `http://localhost:8501`
* **Features**:
  * **Live Prompt Sandbox**: Test custom prompts against the 4-stage pipeline.
  * **Audit Log Explorer**: Search and filter past security events by action, IP, user, and date.
  * **Threat Analytics**: KPI counters and visual threat distribution charts.

---

## 📁 Project Directory Structure

```text
AI-FIREWALL-GATEWAY/
├── app/
│   ├── compliance/
│   │   ├── __init__.py
│   │   └── audit.py              # SQLite & File-based structured audit logger
│   ├── dashboard/
│   │   └── streamlit_app.py      # Streamlit security analytics & sandbox UI
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── credentials.py        # Stage 2: AWS, JWT, DB, API Keys
│   │   ├── credential_gliner.py  # Stage 2: GLiNER zero-shot credential detection
│   │   ├── financial.py          # Stage 3: Credit Cards, Luhn, CVV, Bank AC, IFSC
│   │   ├── intent.py             # Stage 4: Orchestrator for Intent Detection
│   │   ├── intent_transformer.py # Stage 4: PyTorch & HuggingFace Transformer Intent Model
│   │   ├── media_extractor.py    # Media extraction (OCR, PDF, DOCX, XLSX, PPTX, text) & visual redaction
│   │   ├── pii.py                # Stage 1: PII, Presidio, Aadhaar, PAN, Passport
│   │   ├── pipeline.py           # 4-Stage threat detection orchestrator
│   │   └── preprocessor.py       # Multi-encoding & obfuscation decoder
│   ├── policy/
│   │   ├── __init__.py
│   │   └── engine.py             # Policy Decision Engine (ALLOW / REDACT / BLOCK)
│   ├── services/
│   │   ├── media_redaction.py    # Outbound multimodal media sanitization & injection
│   │   └── proxy.py              # Upstream LLM reverse-proxy (OpenAI, Claude, Gemini, Groq, Mistral, Cohere)
│   ├── static/                   # Web interface assets
│   │   ├── chat.js               # Chat UI client-side controller & media comparison
│   │   ├── demo.html             # Attack Simulation Demo HTML
│   │   ├── demo.js               # Attack Simulation Demo controller
│   │   ├── index.html            # Chat UI HTML
│   │   └── styles.css            # Chat UI styles & media comparison cards
│   ├── config.py                 # Pydantic configuration & environment settings
│   ├── logger.py                 # Gateway application logging
│   ├── main.py                   # FastAPI application initialization & routes
│   ├── models.py                 # Pydantic data schemas & response models
│   └── routes.py                 # API route handlers (/api/chat, /api/inspect, /demo, /v1/chat/completions)
├── extension/                    # Chrome Browser Extension (Manifest V3 v2.1.0)
│   ├── icons/                    # Extension icon assets (16, 48, 128px)
│   ├── claude_bridge.js          # ProseMirror bridge for intercepting Claude.ai
│   ├── content.js                # Isolated world content script (DOM events, overlay, sanitized downloads)
│   ├── fetch_interceptor.js      # Main world fetch interceptor for all major LLMs
│   ├── manifest.json             # Extension manifest definition
│   ├── popup.html                # Extension popup UI
│   ├── popup.js                  # Extension toggle & health check logic
│   └── styles.css                # Injected overlay styling
├── logs/                         # SQLite database (audit.db) & audit logs (audit.log)
├── tests/
│   ├── test_evaluation_cases.py  # 19 compliance evaluation test cases
│   ├── test_extension_download.js# 4 Node unit tests for extension sanitized media download
│   ├── test_gateway.py           # 11 FastAPI route & proxy unit tests
│   ├── test_intent_model.py      # 8 Transformer intent model tests
│   └── test_media_redaction.py   # 2 PDF visual redaction & inspect endpoint tests
├── requirements.txt              # Project dependencies
└── README.md                     # Documentation
```

---

## 🚀 Quick Start & How to Run

### Prerequisites

* **Python 3.10+**
* **Google Chrome** or Chromium-based browser (Brave, Edge)
* **Tesseract OCR** (optional, recommended for image text recognition):
  * **macOS**: `brew install tesseract`
  * **Ubuntu / Debian**: `sudo apt install tesseract-ocr`

---

### 1. Installation & Environment Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Sragvi2005/AI-Firewall-Gateway.git
   cd AI-Firewall-Gateway
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Download the spaCy English NLP model:**
   ```bash
   python3 -m spacy download en_core_web_sm
   ```

5. **(Optional) Configure environment variables (`.env`):**
   ```env
   APP_NAME="PromptGuard AI Firewall Gateway"
   HOST=0.0.0.0
   PORT=8000
   DEBUG=True

   # Upstream LLM Configuration
   MOCK_LLM_MODE=True                     # Set to False to route to real upstream LLMs
   OPENAI_API_KEY=sk-...                  # Optional: real OpenAI API key
   ANTHROPIC_API_KEY=sk-ant-...          # Optional: Anthropic Claude API key
   GEMINI_API_KEY=AIza...                 # Optional: Google Gemini API key
   GROQ_API_KEY=gsk_...                   # Optional: Groq API key
   MISTRAL_API_KEY=...                    # Optional: Mistral API key
   COHERE_API_KEY=...                     # Optional: Cohere API key

   # Pipeline Toggles
   ENABLE_STAGE_1_PII=True
   ENABLE_STAGE_2_CREDENTIALS=True
   ENABLE_STAGE_3_FINANCIAL=True
   ENABLE_STAGE_4_INTENT=True
   ENABLE_MEDIA_SCANNING=True
   ```

---

### 2. Running the AI Firewall Gateway (Port 8000)

Start the FastAPI gateway with your virtual environment:

```bash
PYTHONPATH=. uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Once running:
* **Attack Demo Mode**: [http://localhost:8000/demo](http://localhost:8000/demo)
* **Chat UI**: [http://localhost:8000/chat](http://localhost:8000/chat)
* **API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)
* **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

---

### 3. Running the Streamlit Security Dashboard (Port 8501)

In a **separate terminal** (with `.venv` activated):

```bash
PYTHONPATH=. streamlit run app/dashboard/streamlit_app.py
```

* **Dashboard URL**: [http://localhost:8501](http://localhost:8501)

---

### 4. Installing & Using the Chrome Browser Extension

1. Open Google Chrome and navigate to: `chrome://extensions/`
2. Toggle **Developer mode** (top-right corner) to **ON**.
3. Click the **"Load unpacked"** button in the top-left.
4. Select the `extension/` folder located in this repository (`AI-Firewall-Gateway/extension`).
5. Open any supported LLM platform:
   * [ChatGPT](https://chatgpt.com)
   * [Claude](https://claude.ai)
   * [Google Gemini](https://gemini.google.com)
   * [Mistral AI](https://chat.mistral.ai)
   * [Groq Console](https://console.groq.com)
   * [Cohere Coral](https://coral.cohere.com)
6. Try typing a prompt with sensitive information (e.g., `My email is user@test.com and my AWS key is AKIAIOSFODNN7EXAMPLE`) or uploading an image/PDF containing confidential data:
   * PromptGuard intercepts the submission in real time.
   * If sensitive media is found, click **"Download sanitized [filename]"** to download the pixel-redacted copy and submit it safely!

> [!NOTE]
> The Chrome Extension communicates with the FastAPI gateway at `http://localhost:8000`. Ensure the gateway is running.

---

## 📡 API Reference

### 1. Chat UI Endpoint (`POST /api/chat`)
Performs 4-stage inspection, media scanning/pixel redaction, policy verdict, LLM completion, and audit logging in a single call.

```bash
curl -X POST "http://localhost:8000/api/chat" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "provider": "openai",
    "messages": [
      {
        "role": "user",
        "content": "Please verify user account for priya.sharma@gmail.com with phone +91 98765 43210"
      }
    ]
  }'
```

**Response includes security analysis and media comparison metadata:**
```json
{
  "request_id": "4b63ff44-0b42-4f3b-b27b-eef41f92c68a",
  "message": {
    "role": "assistant",
    "content": "Mock LLM Response: Processed sanitized request safely."
  },
  "blocked": false,
  "security": {
    "action": "REDACT",
    "reasons": ["Stage 1: Detected 2 PII entity/entities"],
    "redacted_prompt": "Please verify user account for [EMAIL_ADDRESS] with phone [PHONE_NUMBER]",
    "media_forwarding": {
      "total_attachments": 0,
      "media_redacted": 0,
      "media_clean": 0
    }
  },
  "latency_ms": 32.4
}
```

---

### 2. Attack Demo Unprotected Endpoint (`POST /api/demo/unprotected`)
Directly passes the prompt to the upstream LLM with zero inspection or redaction (used by the `/demo` page to simulate vulnerability exposure).

```bash
curl -X POST "http://localhost:8000/api/demo/unprotected" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [
      {"role": "user", "content": "Send report to priya.sharma@gmail.com"}
    ]
  }'
```

---

### 3. Prompt & Media Inspection Endpoint (`POST /api/inspect`)
Inspects a prompt and optional base64 attachments, returning detected entities, firewall actions, and **downloadable sanitized copies of images and PDFs** without invoking any LLM.

```bash
curl -X POST "http://localhost:8000/api/inspect" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Here is the customer receipt.",
    "attachments": [
      {
        "filename": "receipt.pdf",
        "content_base64": "data:application/pdf;base64,JVBERi0xLjQK...",
        "mime_type": "application/pdf"
      }
    ]
  }'
```

**Response Schema:**
```json
{
  "prompt": "Here is the customer receipt.",
  "action": "REDACT",
  "redacted_prompt": "Here is the customer receipt.",
  "reasons": ["Stage 3: Detected 1 Credit Card"],
  "blocked_by_stage": null,
  "sanitized_attachments": [
    {
      "filename": "receipt.pdf",
      "content_base64": "data:application/pdf;base64,JVBERi0xLjQK...",
      "mime_type": "application/pdf"
    }
  ],
  "media_redaction_failures": [],
  "pipeline": {
    "all_matches": [
      {
        "stage": 3,
        "entity_type": "CREDIT_CARD",
        "text_snippet": "4532-1234-5678-9012",
        "confidence": 0.99,
        "severity": "HIGH",
        "source": "media:receipt.pdf"
      }
    ]
  }
}
```

---

### 4. OpenAI-Compatible Proxy (`POST /v1/chat/completions`)
Drop-in proxy for standard OpenAI client libraries (`openai.OpenAI(base_url="http://localhost:8000/v1")`). Supports multimodal payloads with automatic in-place pixel redaction.

---

### 5. Audit Logs (`GET /api/audit-logs`)
Retrieve recorded audit logs with optional filtering:
```bash
curl "http://localhost:8000/api/audit-logs?action=BLOCK&limit=20"
```

---

### 6. Analytics (`GET /api/analytics`)
Retrieve real-time metrics and stage-by-stage threat detection counts:
```bash
curl "http://localhost:8000/api/analytics"
```

---

## 🧪 Running Automated Tests

PromptGuard includes a comprehensive test suite across Python and Node.js:

### 1. Python Pytest Suite (40 Tests)
Runs compliance evaluation cases, FastAPI routes, Transformer intent classification, and media redaction:

```bash
PYTHONPATH=. pytest -v
```

Expected output:
```text
tests/test_evaluation_cases.py ...................                       [ 47%]
tests/test_gateway.py ...........                                        [ 75%]
tests/test_intent_model.py ........                                      [ 95%]
tests/test_media_redaction.py ..                                         [100%]
======================== 40 passed in 2.27s =========================
```

### 2. Browser Extension Node Unit Tests (4 Tests)
Validates sanitized attachment downloads, composer file clearing, and overlay event handling:

```bash
node --test tests/test_extension_download.js
```

Expected output:
```text
✔ successful sanitized download closes the blocking overlay
✔ failed sanitized download keeps the overlay open
✔ held-back attachment cleanup removes composer files and clears pending state
✔ window capture routes dismissal past the page send-event guard
ℹ tests 4, pass 4
```

---

## 🔒 Audit & Compliance Logging

PromptGuard automatically persists structured audit records for every processed transaction:
1. **SQLite Database**: `logs/audit.db` in table `audit_logs` (indexed for rapid querying and dashboard analytics).
2. **Structured Log File**: `logs/audit.log` (JSON Lines format for SIEM ingestion into Splunk, Datadog, or Elastic Stack).

Each record captures:
* `request_id` (UUID4)
* `timestamp` (ISO 8601 UTC)
* `client_ip` & `user_id`
* `action` (`ALLOW`, `REDACT`, `BLOCK`)
* `original_prompt` & `redacted_prompt`
* `detections_summary` (Stage ID, entity types, snippets, confidence score, severity)
* `latency_ms` & `status_code`

---

## 📄 License

This project is licensed under the MIT License — see the LICENSE file for details.
