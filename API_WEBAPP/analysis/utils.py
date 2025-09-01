import math
import re
import hashlib
from zipfile import ZipFile, BadZipFile

URL_REGEX = re.compile(r"https?://[\w\-\.]+(:\d+)?(/[\w\-\./?%&=+#]*)?", re.IGNORECASE)
IP_REGEX = re.compile(
    r"\b((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for c in freq:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def extract_zip_entry_bytes(apk_path: str, name_contains: str):
    try:
        with ZipFile(apk_path, 'r') as z:
            for n in z.namelist():
                if name_contains.lower() in n.lower():
                    return z.read(n)
    except BadZipFile:
        return None
    return None


def extract_all_strings(data: bytes, min_len: int = 5):
    out, acc = [], []
    for b in data or b"":
        if 32 <= b <= 126:
            acc.append(chr(b))
        else:
            if len(acc) >= min_len:
                out.append(''.join(acc))
            acc = []
    if len(acc) >= min_len:
        out.append(''.join(acc))
    return out


def count_suspicious_strings(strings):
    urls = [s for s in strings if URL_REGEX.search(s)]
    ips = [s for s in strings if IP_REGEX.search(s)]
    keywords = [
    "login","signin","signup","user","username","userid",
    "password","passwd","pwd","passcode","pin","mpin","credential","creds",
    "otp","totp","mfa","2fa","auth","authenticate","token","sessionid",
    "bank","banking","netbanking","ifsc","upi","imps","neft","rtgs","swift",
    "account","accno","acno","iban","sortcode","routing","balance",
    "transaction","txn","transfer","payment","payout","deposit","withdrawal",
    "atm","card","debit","credit","cvc","cvv","expdate","expiry","mastercard",
    "visa","rupay","amex","wallet","paytm","gpay","googlepay","phonepe",
    "bhim","paypal","stripe","cashapp","venmo","zelle",
    "verify","verification","update","reset","recover","unlock","lock",
    "security","secure","confidential","secret","confidentiality",
    "key","privatekey","publickey","apikey","jwt","license","serial",
    "free","prize","winner","lottery","offer","bonus","promotion","deal",
    "click","link","download","install","setup","activate","activation",
    "urgent","alert","important","attention","warning","suspend","disabled",
    "blocked","breach","compromise","hacked","unauthorized","illegal","fraud",
    "exploit","shell","payload","reverse","meterpreter","bind","inject",
    "execute","cmd","command","powershell","bash","sh","exe","dll","so","bin",
    "registry","hkey","startup","boot","autorun","persistence","rootkit",
    "keylogger","logger","capture","screenshot","spy","steal","exfil",
    "encrypt","decrypt","ransom","bitcoin","btc","monero","xmr","crypto",
    "email","mail","outlook","gmail","yahoo","hotmail","imap","smtp","pop3",
    "office365","o365","exchange","webmail","phish","spoof","spoofed",
    "ssn","dob","pan","aadhar","aadhaar","passport","drivinglicense",
    "insurance","medical","policy","tax","irs","income","salary","payroll"
]
    kw_hits = sum(any(k in s.lower() for k in keywords) for s in strings)
    # return {"url_count": len(urls), "ip_count": len(ips), "keyword_hits": int(kw_hits)}
    return {
        "urls": urls,
        "ips": ips,
        "keywords": kw_hits,
        "url_count": len(urls),
        "ip_count": len(ips),
        "keyword_hits": int(kw_hits)
    }


def is_valid_apk(path: str) -> bool:
    try:
        with ZipFile(path, 'r') as z:
            names = set(z.namelist())
            return any(n.endswith('AndroidManifest.xml') for n in names)
    except Exception:
        return False