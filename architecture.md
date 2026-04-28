# SecureAPK Architecture
![Architecture](./images/archi.png)

## Overview

SecureAPK uses a layered APK analysis design. The backend receives the uploaded sample, performs static inspection, enriches the result with threat intelligence, and then combines those signals with a machine-learning prediction.

## System components

- **Landing page**: product presentation and entry point
- **Dashboard**: analyst-facing UI for upload and report review
- **Flask API**: request handling and JSON generation
- **Static analysis module**: manifest, permissions, entropy, strings, icon, and certificate inspection
- **Threat intelligence layer**: VirusTotal and MalwareBazaar hash lookup
- **ML layer**: scikit-learn model loaded from `datamodel.pkl`
- **Explainability layer**: SHAP-based feature attribution
- **Trusted reference data**: `trusted_bank_data.json`
- **Deployment layer**: Gunicorn behind nginx on Lightsail
- **Mobile client**: Flutter entrypoint that calls the public backend

## High-level architecture

```mermaid
flowchart LR
    U[User / Mobile Client] --> W[Landing Page / Dashboard]
    W --> F[Flask app.py]

    F --> S[analysis/static_analyzer.py]
    F --> VT[analysis/vt_lookup.py]
    F --> MB[MalwareBazaar API]
    S --> T[trusted_bank_data.json]
    S --> I[analysis/icon_utils.py]
    S --> U1[analysis/utils.py]

    F --> M[datamodel.pkl]
    F --> X[SHAP explainer]
    F --> R[Final JSON response]

    F --> G[Gunicorn]
    G --> N[nginx]
    N --> A[secureapk.online]
```

## Request lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant Client as Browser / Flutter app
    participant Flask as Flask backend
    participant Static as Static analyzer
    participant VT as VirusTotal
    participant MB as MalwareBazaar
    participant Model as ML model

    Client->>Flask: POST /analyze (APK file)
    Flask->>Flask: validate extension and size
    Flask->>Static: analyze_apk(path)
    Static->>Static: extract manifest, permissions, icon, entropy, strings
    Static-->>Flask: AnalysisResult
    Flask->>VT: lookup SHA-256
    Flask->>MB: lookup SHA-256
    Flask->>Model: predict_proba(feature vector)
    Model-->>Flask: malicious probability
    Flask->>Flask: build SHAP explanations and final score
    Flask-->>Client: JSON report
```

## Data flow

```mermaid
flowchart TD
    A[APK upload] --> B[Temporary file]
    B --> C[Static signals]
    B --> D[Hash generation]
    C --> E[APK metadata]
    C --> F[Permission analysis]
    C --> G[Entropy and string analysis]
    C --> H[Icon similarity]
    D --> I[VirusTotal]
    D --> J[MalwareBazaar]
    E --> K[Feature vector]
    F --> K
    G --> K
    H --> K
    I --> K
    J --> K
    K --> L[ML prediction]
    L --> M[SHAP explanation]
    M --> N[Final verdict]
```

## Runtime modules

### `app.py`
Main Flask application and HTTP route definitions.

### `analysis/static_analyzer.py`
Performs APK parsing and produces the structured `AnalysisResult`.

### `analysis/utils.py`
Utility helpers for hashing, entropy, string extraction, and APK validation checks.

### `analysis/icon_utils.py`
Extracts the most likely icon and computes perceptual hash similarity.

### `analysis/vt_lookup.py`
Looks up the APK SHA-256 in VirusTotal.

### `datamodel.pkl`
Serialized model bundle containing the trained classifier, scaler, and feature ordering.

### `trusted_bank_data.json`
Reference data used for trusted certificate and icon comparison.

### `templates/index.html`
Analyst dashboard used after upload.

### `templates/landing.html`
Public-facing product landing page.

## Feature engineering notes

The backend turns the APK into a fixed feature vector before model inference. The key signals are:

- permission count
- entropy of `classes.dex`
- certificate trust match
- suspicious string count
- icon similarity
- URL/IP counts
- dangerous permission counts

Those signals are then scaled using the saved scaler before the classifier is run.

## Deployment design

SecureAPK is designed to run as a standard WSGI app:

1. `wsgi.py` exposes the Flask app object.
2. Gunicorn binds to a local port.
3. nginx handles public traffic, TLS, and reverse proxying.
4. Lightsail exposes the public IP and domain.

This keeps the application logic unchanged while allowing a production deployment path.

## Operational notes

- Uploaded APKs are handled as temporary files.
- The maximum upload size is set to 50 MB.
- The static analysis pipeline is CPU-heavy but request-scoped.
- External API calls are made during request processing, so network latency affects end-to-end analysis time.
- The dashboard consumes JSON output from `/analyze` and visualizes it in multiple tabs.
