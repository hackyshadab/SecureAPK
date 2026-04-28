import requests
from typing import Dict
def vt_lookup_sha256(sha256: str) -> Dict[str, int]:
    url = sha256
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            return {"detections": detections, "total": total}
        elif resp.status_code == 404:
            return {"detections": 0, "total": 0}
        else:
            return {"detections": 0, "total": 0}
    except requests.RequestException:
        return {"detections": 0, "total": 0}
