import base64
import requests
from flask import current_app
import logging

def check_virustotal(url):
    """
    Checks the URL against the VirusTotal API.
    Returns: (malicious_count, total_engines)
    """
    api_key = current_app.config.get('VIRUSTOTAL_API_KEY')
    if not api_key:
        logging.warning("VirusTotal API Key missing! Check your .env file.")
        return 0, 0

    headers = {"x-apikey": api_key}

    try:
        # Step 1: Look up existing analysis (Fast & accurate for known URLs)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        response = requests.get(endpoint, headers=headers, timeout=20)
        print("VT get status:", response.status_code)

        if response.status_code == 200:
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            print("VT malicious:", malicious, "VT total:", total)
            if total > 0:
                return malicious, total
        
        # Step 2: If not found, submit it so it's scanned for the future
        if response.status_code == 404:
            submit_endpoint = "https://www.virustotal.com/api/v3/urls"
            payload = {"url": url}
            requests.post(submit_endpoint, data=payload, headers=headers, timeout=20)
            print("VT newly submitted to queue. Returning 0 for now.")
            
        return 0, 0

    except requests.exceptions.RequestException as e:
        logging.error(f"VirusTotal API Error: {e}")
        return 0, 0


def check_google_safe_browsing(url):
    """
    Checks URL against Google Safe Browsing API.
    Returns boolean: True if safe, False if unsafe.
    """
    api_key = current_app.config.get('GOOGLE_SAFE_BROWSING_API_KEY')
    if not api_key:
        logging.warning("Google Safe Browsing API Key missing! Check your .env file.")
        return True

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "qr-threat-app",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=20)

        print("GSB status:", response.status_code)
        print("GSB body:", response.text[:300])

        if response.status_code != 200:
            logging.warning(f"Google Safe Browsing failed: {response.status_code}")
            return True

        data = response.json()

        if 'matches' in data and len(data['matches']) > 0:
            print("GSB result: UNSAFE")
            return False

        print("GSB result: SAFE")
        return True

    except requests.exceptions.RequestException as e:
        logging.error(f"GSB API Error: {e}")
        return True

