# SecureAPK Threat Model

## Method

This threat model uses a STRIDE-style approach against the main assets, entry points, and processing stages of SecureAPK.

## Assets

- APK files uploaded by users
- API keys for VirusTotal and MalwareBazaar
- ML bundle and supporting model artifacts
- trusted reference data
- generated reports
- server resources on Lightsail
- the public reputation of the service

## Entry points

- `GET /`
- `GET /dashboard`
- `GET /health`
- `POST /analyze`
- static asset delivery
- reverse proxy and TLS termination
- third-party API calls

## STRIDE analysis

### Spoofing
**Threats**
- forged APK identity through altered labels, package names, or icons
- fake or replayed external reputation results if upstream responses are not validated
- impersonation of a known banking app by copying assets and metadata

**Current controls**
- certificate fingerprint checks
- icon similarity checks
- package and label extraction
- remote reputation lookups

**Mitigations**
- treat static identity signals as hints, not proof
- add stronger certificate pinning/reference matching over time
- log source hashes and analysis timestamps

### Tampering
**Threats**
- modified APK contents
- tampered model or pickle artifacts
- dependency tampering during installation
- malicious replacement of analysis inputs or trusted reference data

**Current controls**
- server-side hash generation
- limited upload path handling
- pinned dependency versions

**Mitigations**
- verify artifact hashes before deployment
- store model files in controlled release packages
- keep the deployment host patched
- isolate write permissions for runtime folders

### Repudiation
**Threats**
- users deny uploading a sample
- analysts dispute a verdict
- no audit trail for request origin or request timing

**Current controls**
- JSON report generation
- dashboard history view

**Mitigations**
- add request IDs and structured logs
- store only essential metadata
- avoid verbose logging of raw samples

### Information disclosure
**Threats**
- exposed API keys in source
- leaking APK contents or indicators in logs
- disclosure of sensitive app metadata
- unauthorized access to uploaded samples or reports

**Current controls**
- temporary upload handling
- health endpoint separated from analysis output
- no automatic execution of uploaded APKs

**Mitigations**
- move secrets to environment variables before public release
- protect public endpoints with TLS
- limit report retention
- scrub logs and error pages

### Denial of service
**Threats**
- oversized APK uploads
- archive bombs or malformed APKs
- repeated expensive analysis requests
- third-party API rate limits
- CPU pressure from entropy, hashing, SHAP, and icon parsing

**Current controls**
- 50 MB upload limit
- APK extension validation
- temporary-file cleanup

**Mitigations**
- rate-limit requests
- add queueing for expensive jobs if needed later
- monitor API failures and timeout behavior
- place the app behind nginx and a process supervisor

### Elevation of privilege
**Threats**
- parser vulnerabilities in APK inspection libraries
- unexpected behavior in image or archive handling
- remote code execution through dependency compromise

**Current controls**
- request-scoped processing
- no direct command execution of uploaded files

**Mitigations**
- run the service as a dedicated low-privilege user
- keep dependencies updated
- isolate the app from sensitive host paths
- review native libraries before upgrading

## Attack surface summary

| Surface | Risk | Priority |
|---|---|---|
| `POST /analyze` | high CPU, upload abuse, parser edge cases | high |
| hardcoded API keys | secret exposure | high |
| model files | tampering / deserialization risk | high |
| third-party APIs | dependency on availability and rate limits | medium |
| dashboard frontend | UI injection if future dynamic content is added | medium |
| static assets | low direct risk | low |

## Mitigation priorities

1. Remove secrets from public commits.
2. Keep upload and temp-file handling tightly bounded.
3. Add request logging and rate control.
4. Verify model and dependency artifacts before deployment.
5. Continue using TLS and a reverse proxy on the public domain.

## Residual risk

Even with controls in place, APK analysis remains a hostile-input problem. Residual risk mainly comes from malformed files, parser bugs, and upstream API outages. The recommended operational response is to keep the system patched, monitor failures, and treat the verdict as analyst support rather than absolute truth.
