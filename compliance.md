# SecureAPK Compliance Guide

This document summarizes practical compliance and security-aligned operating guidance for SecureAPK. It is not legal advice.

## Objectives

- keep the platform predictable
- protect user-submitted APK files
- reduce secret exposure
- preserve analyst trust in the report
- make the repository suitable for professional review

## Security and compliance baseline

### 1. OWASP-aligned web application hygiene
SecureAPK should be reviewed against common OWASP controls:

- validate all uploads
- enforce file type and size limits
- use server-side validation, not only client-side checks
- keep third-party libraries updated
- protect against insecure deserialization risk from model artifacts
- log failures without leaking secrets


### 2. Data protection
APK uploads may contain app metadata, code, embedded URLs, certificates, and user-related indicators. Treat the uploaded sample as potentially sensitive.

Recommended handling:
- store files temporarily only
- delete temporary uploads after processing
- avoid keeping raw samples in logs
- do not expose report data to unauthorized users
- apply retention controls if reports are persisted

### 3. Malware sample safety
SecureAPK is an analysis tool, so uploaded samples should be handled as untrusted objects.

Controls to keep in place:
- do not auto-execute APK contents
- keep parsing libraries isolated in the analysis environment
- limit file size
- avoid unrestricted archive extraction
- run the service with minimal OS privileges

### 4. Dependency governance
The project pins runtime packages for compatibility with the serialized ML bundle.

Good practice:
- record the exact dependency set in `requirements-lightsail.txt`
- test upgrades in a separate branch
- review native packages such as Pillow, cryptography, and scikit-learn carefully
- regenerate the model bundle only when the environment is intentionally changed

### 5. Third-party API compliance
VirusTotal and MalwareBazaar are external services with their own policies, quotas, and acceptable-use terms.

Operational guardrails:
- respect rate limits
- handle missing or incomplete responses gracefully
- avoid retry storms
- cache only when allowed by the provider terms

### 6. Logging and traceability
A professional deployment should maintain enough traceability to diagnose incidents without exposing secrets.

Recommended logs:
- request timestamp
- filename or request ID
- analysis duration
- success/failure state
- external API status
- model decision summary

Avoid logging:
- full API keys
- raw APK content
- sensitive analyst comments
- full response payloads if they include unnecessary detail

### 7. Accessibility and maintainability
The landing page and dashboard should remain readable on smaller screens and usable by analysts on different devices.

Good review points:
- responsive grids
- sufficient contrast
- clear button labels
- visible tab state
- keyboard-friendly form controls

## Control checklist

| Area | Minimum control |
|---|---|
| Uploads | size and type validation |
| Secrets | environment-based storage |
| Runtime | WSGI server and reverse proxy |
| Data | temporary handling and deletion |
| Dependencies | pinned versions and change review |
| Reporting | clear JSON and UI output |
| External APIs | quota-aware handling |
| Repository | documented structure and release notes |
