import requests
from typing import Dict
VT_API_KEY = "a6ee8c2946fe3bdd5aa9bef1f807a49daf393852742e554dbea6917682af9b5e"
VT_BASE_URL = "https://www.virustotal.com/api/v3/files/"
HEADERS = {"x-apikey": VT_API_KEY}
def vt_lookup_sha256(sha256: str) -> Dict[str, int]:
    url = VT_BASE_URL + sha256
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.get(k, 0) for k in ["harmless", "malicious", "suspicious", "undetected", "timeout"])
            total = max(total, 1)  # avoid division by zero
            return {"detections": detections, "total": total}
        elif resp.status_code == 404:
            return {"detections": 0, "total": 0}
        else:
            return {"detections": 0, "total": 0}
    except requests.RequestException:
        return {"detections": 0, "total": 0}
