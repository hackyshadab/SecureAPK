import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", os.urandom(32))
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 50 * 1024 * 1024))  # 50 MB
    UPLOAD_EXTENSIONS = {".apk"}
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", os.path.join(BASE_DIR, "_uploads"))
    TRUSTED_DATA_FILE = os.environ.get("TRUSTED_DATA_FILE", os.path.join(BASE_DIR, "model", "trusted_bank_data.json"))

    # Security headers
    CONTENT_SECURITY_POLICY = (
        "default-src 'none'; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)