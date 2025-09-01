import json
import os
from dataclasses import dataclass, asdict
from zipfile import ZipFile
from .utils import sha256_file, shannon_entropy, extract_zip_entry_bytes, extract_all_strings, count_suspicious_strings
from .icon_utils import extract_primary_icon, icon_phash, similarity_score
from .vt_lookup import vt_lookup_sha256

# Lazy/optional heavy deps
try:
    from androguard.core.apk import APK as AG_APK
except ImportError:
    try:
        from androguard.core.bytecodes.apk import APK as AG_APK  # older versions
    except Exception:
        AG_APK = None

try:
    from apkutils2 import APK as AU_APK
except Exception:
    AU_APK = None


@dataclass
class AnalysisResult:
    sha256: str
    package: str | None
    app_label: str | None
    version_name: str | None
    version_code: str | None
    permissions: list
    dangerous_permissions: list
    cert_fingerprint: str | None
    cert_trusted_match: bool
    icon_hash: str | None
    icon_similarity_score: float
    entropy_classes_dex: float
    suspicious: dict
    vt: dict

    def to_dict(self):
        return asdict(self)


DANGEROUS_PERMS = {
    'android.permission.READ_SMS', 'android.permission.RECEIVE_SMS', 'android.permission.SEND_SMS',
    'android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS',
    'android.permission.READ_PHONE_STATE', 'android.permission.CALL_PHONE',
    'android.permission.PROCESS_OUTGOING_CALLS', 'android.permission.RECORD_AUDIO',
    'android.permission.READ_EXTERNAL_STORAGE', 'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.REQUEST_INSTALL_PACKAGES',
}


def _load_trusted_data(json_path: str) -> dict:
    if not os.path.exists(json_path):
        return {"trusted_certs": [], "trusted_icons": [], "bank_packages": []}
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def _extract_manifest_with_androguard(apk_path: str):
    if not AG_APK:
        return None
    try:
        a = AG_APK(apk_path)
        pkg = a.package
        label = a.get_app_name()
        version_name = a.get_androidversion_name()
        version_code = str(a.get_androidversion_code()) if a.get_androidversion_code() else None
        perms = list(a.get_permissions() or [])
        fp = None
        try:
            certs = a.get_certificates_der_v2() or a.get_certificates_der_v3() or a.get_certificates_der_v1()
            if certs:
                import hashlib
                fp = hashlib.sha256(certs[0]).hexdigest()
        except Exception:
            pass
        icon_hint = None
        try:
            icon_hint = a.get_app_icon()
        except Exception:
            pass
        return {
            'package': pkg, 'label': label, 'version_name': version_name, 'version_code': version_code,
            'permissions': perms, 'cert_fingerprint': fp, 'icon_hint': icon_hint,
        }
    except Exception:
        return None


def _extract_manifest_with_apkutils(apk_path: str):
    if not AU_APK:
        return None
    try:
        a = AU_APK(apk_path)
        manifest = a.get_manifest()
        pkg = manifest['manifest']['@package']
        app = manifest['manifest'].get('application', {})
        label = app.get('@android:label') or app.get('@label')
        version_name = manifest['manifest'].get('@android:versionName') or manifest['manifest'].get('@versionName')
        version_code = manifest['manifest'].get('@android:versionCode') or manifest['manifest'].get('@versionCode')
        perms = []
        uses = manifest['manifest'].get('uses-permission', [])
        if isinstance(uses, dict):
            uses = [uses]
        for p in uses:
            name = p.get('@android:name') or p.get('@name')
            if name:
                perms.append(name)
        icon_hint = None
        try:
            icon_hint = a.get_app_icon()
        except Exception:
            pass
        fp = None
        try:
            import hashlib
            with ZipFile(apk_path, 'r') as z:
                for n in z.namelist():
                    u = n.upper()
                    if u.startswith('META-INF/') and (u.endswith('.RSA') or u.endswith('.DSA') or u.endswith('.EC')):
                        fp = hashlib.sha256(z.read(n)).hexdigest()
                        break
        except Exception:
            pass
        return {
            'package': pkg, 'label': label, 'version_name': version_name,
            'version_code': str(version_code) if version_code else None,
            'permissions': perms, 'cert_fingerprint': fp, 'icon_hint': icon_hint,
        }
    except Exception:
        return None


def analyze_apk(apk_path: str, trusted_data_path: str, vt_enabled: bool = False) -> AnalysisResult:
    meta = _extract_manifest_with_androguard(apk_path) or _extract_manifest_with_apkutils(apk_path) or {}

    pkg = meta.get('package')
    label = meta.get('label')
    version_name = meta.get('version_name')
    version_code = meta.get('version_code')
    perms = meta.get('permissions', [])

    dangerous = sorted(set(perms).intersection(DANGEROUS_PERMS))

    classes = extract_zip_entry_bytes(apk_path, 'classes.dex')
    entropy = shannon_entropy(classes) if classes else 0.0

    strings = extract_all_strings(classes) if classes else []
    if not strings:
        manifest_bytes = extract_zip_entry_bytes(apk_path, 'AndroidManifest.xml') or b''
        strings = extract_all_strings(manifest_bytes)
    suspicious = count_suspicious_strings(strings)

    icon_hint = meta.get('icon_hint')
    icon_bytes, icon_img = extract_primary_icon(apk_path, icon_hint)
    icon_hash = icon_phash(icon_img) if icon_img else None

    sha256 = sha256_file(apk_path)

    vt = vt_lookup_sha256(sha256) if vt_enabled else {"detections": 0, "total": 0}

    trusted = _load_trusted_data(trusted_data_path)
    cert_fp = meta.get('cert_fingerprint')
    trusted_certs = {c.lower() for c in trusted.get('trusted_certs', [])}
    cert_match = (cert_fp and cert_fp.lower() in trusted_certs) or False

    icon_sim = 0.0
    if icon_hash:
        for h in trusted.get('trusted_icons', []):
            icon_sim = max(icon_sim, similarity_score(icon_hash, h))

    return AnalysisResult(
        sha256=sha256,
        package=pkg,
        app_label=label,
        version_name=version_name,
        version_code=version_code,
        permissions=perms,
        dangerous_permissions=dangerous,
        cert_fingerprint=cert_fp,
        cert_trusted_match=bool(cert_match),
        icon_hash=icon_hash,
        icon_similarity_score=float(icon_sim),
        entropy_classes_dex=float(entropy),
        suspicious=suspicious,
        vt=vt,
    )