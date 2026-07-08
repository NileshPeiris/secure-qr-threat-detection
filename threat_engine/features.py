import urllib.parse
import re
import math

def extract_features(url):
    """
    Extracts numerical features from a URL for the ML model.
    """
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    
    features = {
        'length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_at_symbols': url.count('@'),
        'num_query_params': len(urllib.parse.parse_qs(parsed.query)),
        'has_ip': 1 if is_ip_address(domain) else 0,
        'has_https': 1 if parsed.scheme == 'https' else 0,
        'entropy': calculate_entropy(url)
    }
    
    return features

def is_ip_address(domain):
    # Basic check if the domain looks like an IPv4
    parts = domain.split('.')
    if len(parts) == 4:
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            pass
    return False

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x))/len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return float(entropy)
