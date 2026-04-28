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
