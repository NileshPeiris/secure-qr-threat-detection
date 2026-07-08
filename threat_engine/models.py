import os
import re
import math
import joblib
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix

# --------------------------------------------------
# LOAD MODEL FILES
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "models", "vectorizer.pkl")

model = None
vectorizer = None

try:
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
    else:
        print("Model or vectorizer file not found.")
except Exception as e:
    print(f"Error loading models: {e}")

# --------------------------------------------------
# IMPROVED KEYWORDS / TLDS / SHORTENERS
# --------------------------------------------------
suspicious_keywords = [
    "login", "signin", "sign-in", "logon", "auth", "authenticate",
    "verify", "verification", "confirm", "account", "secure", "security",
    "password", "passcode", "pin", "otp", "2fa", "mfa",

    "alert", "warning", "urgent", "immediate", "important", "suspended",
    "locked", "restricted", "limited", "expired", "reactivate", "unlock",

    "bank", "payment", "billing", "invoice", "refund", "transaction",
    "credit", "debit", "wallet", "statement", "tax", "claim",

    "paypal", "apple", "microsoft", "google", "facebook", "instagram",
    "netflix", "amazon", "outlook", "office365", "dhl", "fedex", "whatsapp",

    "download", "setup", "install", "patch", "update", "update-now",
    "exe", "apk", "zip", "rar", "iso", "docm", "xlsm", "js",
    "crack", "keygen", "activate", "loader", "payload",

    "free", "gift", "offer", "bonus", "win", "winner", "prize", "reward",
    "promo", "coupon",

    "redirect", "click", "tracking", "secure-login", "access", "portal"
]

suspicious_tlds = {
    "xyz", "top", "click", "gq", "tk", "ml", "cf", "ga", "work", "support",
    "fit", "party", "country", "stream", "download", "loan", "win", "men"
}

shortener_domains = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "buff.ly",
    "rebrand.ly", "is.gd", "cutt.ly", "shorturl.at"
}

# --------------------------------------------------
# FEATURE HELPERS
# --------------------------------------------------
def shannon_entropy(text):
    if not text:
        return 0.0
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probs if p > 0)

def has_ip_address(netloc):
    return int(bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}(:\d+)?", netloc)))

def count_digits(text):
    return sum(ch.isdigit() for ch in text)

def count_letters(text):
    return sum(ch.isalpha() for ch in text)

def count_special_chars(text):
    return sum(not ch.isalnum() for ch in text)

def keyword_features(url):
    url = url.lower()
    binary_features = [int(word in url) for word in suspicious_keywords]
    keyword_count = sum(binary_features)
    return binary_features + [keyword_count]

def extract_url_parts(url):
    parsed = urlparse(url)
    scheme = parsed.scheme or ""
    netloc = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""

    if not netloc and path and "." in path:
        netloc = path
        path = ""

    domain_parts = netloc.split(".") if netloc else []
    tld = domain_parts[-1] if len(domain_parts) >= 2 else ""
    subdomain_count = max(len(domain_parts) - 2, 0)

    return {
        "scheme": scheme,
        "netloc": netloc,
        "path": path,
        "query": query,
        "tld": tld,
        "subdomain_count": subdomain_count
    }

def url_features(url):
    parts = extract_url_parts(url)
    netloc = parts["netloc"]
    path = parts["path"]
    query = parts["query"]
    tld = parts["tld"]

    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("/"),
        int(bool(re.search(r"\d", url))),
        int("https" in url),

        len(netloc),
        len(path),
        len(query),
        count_digits(url),
        count_letters(url),
        count_special_chars(url),
        url.count("%"),
        url.count("&"),
        url.count("_"),
        url.count("~"),
        url.count(":"),
        url.count(";"),

        int(url.startswith("http://")),
        int(url.startswith("https://")),
        int(has_ip_address(netloc)),
        parts["subdomain_count"],
        int(tld in suspicious_tlds),
        int(netloc in shortener_domains),
        int("@" in netloc or "@" in path),
        int("//" in path),
        int(bool(re.search(r"(login|verify|secure|update|bank|paypal|account)", url))),
        shannon_entropy(url),
        shannon_entropy(netloc),
        shannon_entropy(path),

        int(len(re.findall(r"\d+", url)) > 2),
        int(url.count("-") > 3),
        int(url.count(".") > 3),
        int(len(query) > 30),
    ]

# --------------------------------------------------
# PREDICTION
# --------------------------------------------------
def predict_url_ml(url):
    if model is None or vectorizer is None:
        return {
            "label": "Error",
            "safe_prob": 1.0,
            "phishing_prob": 0.0,
            "malware_prob": 0.0,
            "keyword_score": 0
        }

    try:
        url_clean = str(url).lower().strip()

        text_feat = vectorizer.transform([url_clean])
        struct_feat = csr_matrix([url_features(url_clean) + keyword_features(url_clean)])
        combined = hstack([text_feat, struct_feat]).tocsr()

        prediction = model.predict(combined)[0]

        # Some models may not support predict_proba
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(combined)[0]
            safe_prob = float(probabilities[0]) if len(probabilities) > 0 else 0.0
            phishing_prob = float(probabilities[1]) if len(probabilities) > 1 else 0.0
            malware_prob = float(probabilities[2]) if len(probabilities) > 2 else 0.0
        else:
            safe_prob = 1.0 if prediction == 0 else 0.0
            phishing_prob = 1.0 if prediction == 1 else 0.0
            malware_prob = 1.0 if prediction == 2 else 0.0

        keyword_score = sum(1 for kw in suspicious_keywords if kw in url_clean)

        label_map = {
            0: "Safe",
            1: "Phishing",
            2: "Malware"
        }

        return {
            "label": label_map.get(prediction, "Unknown"),
            "safe_prob": safe_prob,
            "phishing_prob": phishing_prob,
            "malware_prob": malware_prob,
            "keyword_score": keyword_score
        }

    except Exception as e:
        print(f"ML Prediction error: {e}")
        return {
            "label": "Error",
            "safe_prob": 1.0,
            "phishing_prob": 0.0,
            "malware_prob": 0.0,
            "keyword_score": 0
        }

def get_ml_risk_score(url):
    result = predict_url_ml(url)
    return int((result["phishing_prob"] + result["malware_prob"]) * 100)