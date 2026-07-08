import base64
import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("VIRUSTOTAL_API_KEY")
url = "http://eicar.org"
url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

headers = {"x-apikey": api_key}
print(f"Requesting VT for {url_id}...")
response = requests.get(endpoint, headers=headers)
print(response.status_code)
if response.status_code == 200:
    stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    print("Stats:", stats)
else:
    print("Error:", response.text)
