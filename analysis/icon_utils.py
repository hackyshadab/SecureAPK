from zipfile import ZipFile
from io import BytesIO
from PIL import Image
import imagehash


def extract_primary_icon(apk_path: str, icon_path_hint: str | None = None):
    with ZipFile(apk_path, 'r') as z:
        names = z.namelist()
        if icon_path_hint and icon_path_hint in names:
            data = z.read(icon_path_hint)
            return data, Image.open(BytesIO(data))
        # fallback pick largest png/webp under res/mipmap*/drawable*
        candidates = []
        for n in names:
            nl = n.lower()
            if nl.startswith('res/') and (nl.endswith('.png') or nl.endswith('.webp')) and ('mipmap' in nl or 'drawable' in nl):
                try:
                    data = z.read(n)
                    img = Image.open(BytesIO(data))
                    candidates.append((n, img.size[0]*img.size[1], data, img))
                except Exception:
                    continue
        if not candidates:
            return None, None
        candidates.sort(key=lambda x: x[1], reverse=True)
        _, _, data, img = candidates[0]
        return data, img

